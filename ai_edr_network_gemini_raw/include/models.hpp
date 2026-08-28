#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

struct ConnectionEvent {
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t pid{};
    std::string process_name;

    std::string local_ip;
    std::uint16_t local_port{};

    std::string remote_ip;
    std::uint16_t remote_port{};

    std::string protocol;
    std::string state;
};

struct RawNetworkReport {
    std::chrono::system_clock::time_point generated_at;
    std::uint32_t target_pid{};
    std::string process_name;
    int observation_duration_seconds{};
    std::vector<ConnectionEvent> observations;
};
