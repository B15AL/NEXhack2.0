#include "collector.hpp"

#ifdef _WIN32

#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
    std::string ipv4_to_string(DWORD address) {
        IN_ADDR addr{};
        addr.S_un.S_addr = address;

        char buffer[INET_ADDRSTRLEN]{};
        if (InetNtopA(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
            return {};
        }
        return buffer;
    }

    std::string tcp_state_to_string(DWORD state) {
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
            case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
            default: return "UNKNOWN";
        }
    }

    std::vector<ConnectionEvent> snapshot_tcp(
        std::uint32_t pid,
        const std::string& process_name
    ) {
        DWORD size = 0;
        DWORD result = GetExtendedTcpTable(
            nullptr, &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0
        );

        if (result != ERROR_INSUFFICIENT_BUFFER) {
            return {};
        }

        std::vector<BYTE> buffer(size);

        result = GetExtendedTcpTable(
            buffer.data(), &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0
        );

        if (result != NO_ERROR) {
            return {};
        }

        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        std::vector<ConnectionEvent> events;
        const auto now = std::chrono::system_clock::now();

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];

            if (row.dwOwningPid != pid) {
                continue;
            }

            // Ignore listeners and sockets with no remote endpoint.
            if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwRemoteAddr == 0) {
                continue;
            }

            ConnectionEvent event;
            event.timestamp = now;
            event.pid = pid;
            event.process_name = process_name;
            event.local_ip = ipv4_to_string(row.dwLocalAddr);
            event.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
            event.remote_ip = ipv4_to_string(row.dwRemoteAddr);
            event.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
            event.protocol = "TCP";
            event.state = tcp_state_to_string(row.dwState);

            events.push_back(std::move(event));
        }

        return events;
    }

    std::vector<ConnectionEvent> snapshot_udp(
        std::uint32_t pid,
        const std::string& process_name
    ) {
        DWORD size = 0;
        DWORD result = GetExtendedUdpTable(
            nullptr, &size, FALSE, AF_INET,
            UDP_TABLE_OWNER_PID, 0
        );

        if (result != ERROR_INSUFFICIENT_BUFFER) {
            return {};
        }

        std::vector<BYTE> buffer(size);

        result = GetExtendedUdpTable(
            buffer.data(), &size, FALSE, AF_INET,
            UDP_TABLE_OWNER_PID, 0
        );

        if (result != NO_ERROR) {
            return {};
        }

        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        std::vector<ConnectionEvent> events;
        const auto now = std::chrono::system_clock::now();

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];

            if (row.dwOwningPid != pid) {
                continue;
            }

            ConnectionEvent event;
            event.timestamp = now;
            event.pid = pid;
            event.process_name = process_name;
            event.local_ip = ipv4_to_string(row.dwLocalAddr);
            event.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
            event.protocol = "UDP";
            event.state = "BOUND";

            events.push_back(std::move(event));
        }

        return events;
    }
}

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t pid,
    const std::string& process_name,
    int duration_seconds,
    int interval_seconds
) {
    std::vector<ConnectionEvent> all_events;

    if (duration_seconds <= 0 || interval_seconds <= 0) {
        return all_events;
    }

    const int iterations = (duration_seconds + interval_seconds - 1)
                           / interval_seconds;

    for (int i = 0; i < iterations; ++i) {
        auto tcp_events = snapshot_tcp(pid, process_name);
        auto udp_events = snapshot_udp(pid, process_name);

        all_events.insert(
            all_events.end(),
            std::make_move_iterator(tcp_events.begin()),
            std::make_move_iterator(tcp_events.end())
        );

        all_events.insert(
            all_events.end(),
            std::make_move_iterator(udp_events.begin()),
            std::make_move_iterator(udp_events.end())
        );

        if (i + 1 < iterations) {
            std::this_thread::sleep_for(
                std::chrono::seconds(interval_seconds)
            );
        }
    }

    return all_events;
}

#else

std::vector<ConnectionEvent> NetworkCollector::collect(
    std::uint32_t,
    const std::string&,
    int,
    int
) {
    throw std::runtime_error(
        "The current NetworkCollector implementation is Windows-only."
    );
}

#endif
