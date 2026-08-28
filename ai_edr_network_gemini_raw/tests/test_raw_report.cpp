#include "raw_report.hpp"

#include <cassert>
#include <chrono>
#include <iostream>

int main() {
    RawNetworkReport report;

    report.generated_at =
        std::chrono::system_clock::now();

    report.target_pid = 1234;
    report.process_name = "test.exe";
    report.observation_duration_seconds = 30;

    ConnectionEvent e;

    e.timestamp =
        std::chrono::system_clock::now();

    e.pid = 1234;
    e.process_name = "test.exe";
    e.local_ip = "192.0.2.10";
    e.local_port = 50000;
    e.remote_ip = "203.0.113.10";
    e.remote_port = 443;
    e.protocol = "TCP";
    e.state = "ESTABLISHED";

    report.observations.push_back(e);

    const std::string json =
        raw_report_to_json(report);

    assert(
        json.find("\"observations\"") !=
        std::string::npos
    );

    assert(
        json.find("\"remote_ip\": \"203.0.113.10\"") !=
        std::string::npos
    );

    assert(
        json.find("\"remote_port\": 443") !=
        std::string::npos
    );

    std::cout
        << "Raw report tests passed.\n";

    return 0;
}
