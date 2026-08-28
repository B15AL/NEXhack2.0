#include "collector.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32

#define NOMINMAX
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
std::string ipv4_to_string(DWORD address) {
    IN_ADDR addr{};
    addr.S_un.S_addr = address;
    char buffer[INET_ADDRSTRLEN]{};

    if (InetNtopA(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr)
        return {};

    return buffer;
}

std::string tcp_state(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECEIVED";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        default: return "UNKNOWN";
    }
}

void collect_tcp(
    std::uint32_t pid,
    const std::string& process_name,
    std::vector<ConnectionEvent>& out
) {
    DWORD size = 0;

    if (GetExtendedTcpTable(
            nullptr, &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0)
        != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<BYTE> buffer(size);

    if (GetExtendedTcpTable(
            buffer.data(), &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0)
        != NO_ERROR) {
        return;
    }

    auto* table =
        reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    const auto now = std::chrono::system_clock::now();

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];

        if (row.dwOwningPid != pid ||
            row.dwState == MIB_TCP_STATE_LISTEN ||
            row.dwRemoteAddr == 0) {
            continue;
        }

        ConnectionEvent e;
        e.timestamp = now;
        e.pid = pid;
        e.process_name = process_name;
        e.local_ip = ipv4_to_string(row.dwLocalAddr);
        e.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        e.remote_ip = ipv4_to_string(row.dwRemoteAddr);
        e.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        e.protocol = "TCP";
        e.state = tcp_state(row.dwState);

        out.push_back(std::move(e));
    }
}
}

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t pid,
    const std::string& process_name,
    int duration_seconds,
    int interval_seconds
) {
    std::vector<ConnectionEvent> events;

    const int iterations =
        std::max(1, (duration_seconds + interval_seconds - 1) /
                         interval_seconds);

    for (int i = 0; i < iterations; ++i) {
        collect_tcp(pid, process_name, events);

        if (i + 1 < iterations)
            std::this_thread::sleep_for(
                std::chrono::seconds(interval_seconds));
    }

    return events;
}

#elif defined(__linux__)

namespace {
std::string hex_ipv4(const std::string& hex) {
    if (hex.size() != 8)
        return {};

    unsigned int value = 0;

    try {
        value = std::stoul(hex, nullptr, 16);
    } catch (...) {
        return {};
    }

    const unsigned int a = value & 0xff;
    const unsigned int b = (value >> 8) & 0xff;
    const unsigned int c = (value >> 16) & 0xff;
    const unsigned int d = (value >> 24) & 0xff;

    return std::to_string(a) + "." +
           std::to_string(b) + "." +
           std::to_string(c) + "." +
           std::to_string(d);
}

void parse_table(
    std::uint32_t pid,
    const std::string& process_name,
    const std::string& path,
    const std::string& protocol,
    std::vector<ConnectionEvent>& out
) {
    std::ifstream file(path);

    if (!file)
        return;

    std::string line;
    std::getline(file, line);

    const auto now = std::chrono::system_clock::now();

    while (std::getline(file, line)) {
        std::istringstream ss(line);

        std::string slocal;
        std::string sremote;
        std::string state;

        if (!(ss >> slocal >> sremote >> state))
            continue;

        const auto local_colon = slocal.find(':');
        const auto remote_colon = sremote.find(':');

        if (local_colon == std::string::npos ||
            remote_colon == std::string::npos)
            continue;

        const std::string local_ip =
            hex_ipv4(slocal.substr(0, local_colon));

        const std::string remote_ip =
            hex_ipv4(sremote.substr(0, remote_colon));

        unsigned int local_port = 0;
        unsigned int remote_port = 0;

        try {
            local_port =
                std::stoul(
                    slocal.substr(local_colon + 1),
                    nullptr,
                    16);

            remote_port =
                std::stoul(
                    sremote.substr(remote_colon + 1),
                    nullptr,
                    16);
        } catch (...) {
            continue;
        }

        if (remote_ip == "0.0.0.0" && remote_port == 0)
            continue;

        ConnectionEvent e;
        e.timestamp = now;
        e.pid = pid;
        e.process_name = process_name;
        e.local_ip = local_ip;
        e.local_port =
            static_cast<std::uint16_t>(local_port);
        e.remote_ip = remote_ip;
        e.remote_port =
            static_cast<std::uint16_t>(remote_port);
        e.protocol = protocol;
        e.state = state;

        out.push_back(std::move(e));
    }
}
}

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t pid,
    const std::string& process_name,
    int duration_seconds,
    int interval_seconds
) {
    std::vector<ConnectionEvent> events;

    const int iterations =
        std::max(1, (duration_seconds + interval_seconds - 1) /
                         interval_seconds);

    const std::string base =
        "/proc/" + std::to_string(pid) + "/net/";

    for (int i = 0; i < iterations; ++i) {
        parse_table(
            pid, process_name,
            base + "tcp", "TCP", events);

        parse_table(
            pid, process_name,
            base + "udp", "UDP", events);

        if (i + 1 < iterations)
            std::this_thread::sleep_for(
                std::chrono::seconds(interval_seconds));
    }

    return events;
}

#elif defined(__APPLE__)

namespace {
void collect_lsof(
    std::uint32_t pid,
    const std::string& process_name,
    std::vector<ConnectionEvent>& out
) {
    const std::string command =
        "lsof -nP -a -p " +
        std::to_string(pid) +
        " -i 2>/dev/null";

    FILE* pipe = popen(command.c_str(), "r");

    if (!pipe)
        return;

    char buffer[4096];
    const auto now = std::chrono::system_clock::now();

    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);

        if (line.find("COMMAND") == 0)
            continue;

        std::istringstream ss(line);

        std::string command_name, lpid, user, fd;
        std::string type, device, size_offset, node, name;

        if (!(ss >> command_name >> lpid >> user >> fd
              >> type >> device >> size_offset >> node >> name))
            continue;

        const auto arrow = name.find("->");

        if (arrow == std::string::npos)
            continue;

        const std::string remote =
            name.substr(arrow + 2);

        const auto pos = remote.rfind(':');

        if (pos == std::string::npos)
            continue;

        const std::string remote_ip =
            remote.substr(0, pos);

        std::uint16_t remote_port = 0;

        try {
            remote_port =
                static_cast<std::uint16_t>(
                    std::stoul(remote.substr(pos + 1)));
        } catch (...) {
            continue;
        }

        ConnectionEvent e;
        e.timestamp = now;
        e.pid = pid;
        e.process_name = process_name;
        e.remote_ip = remote_ip;
        e.remote_port = remote_port;
        e.protocol = (type == "UDP") ? "UDP" : "TCP";
        e.state = "UNKNOWN";

        out.push_back(std::move(e));
    }

    pclose(pipe);
}
}

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t pid,
    const std::string& process_name,
    int duration_seconds,
    int interval_seconds
) {
    std::vector<ConnectionEvent> events;

    const int iterations =
        std::max(1, (duration_seconds + interval_seconds - 1) /
                         interval_seconds);

    for (int i = 0; i < iterations; ++i) {
        collect_lsof(pid, process_name, events);

        if (i + 1 < iterations)
            std::this_thread::sleep_for(
                std::chrono::seconds(interval_seconds));
    }

    return events;
}

#else

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t,
    const std::string&,
    int,
    int
) {
    throw std::runtime_error(
        "Unsupported operating system.");
}

#endif
