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

    std::string protocol; // TCP or UDP
    std::string state;
};

struct PeriodicEndpoint {
    std::string endpoint;
    std::size_t observations{};
    double mean_interval_seconds{};
    double relative_interval_std{};
};

struct NetworkFeatures {
    std::size_t total_observations{};
    std::size_t unique_remote_ips{};
    std::size_t unique_remote_ports{};
    std::size_t tcp_observations{};
    std::size_t udp_observations{};

    std::vector<std::string> repeated_endpoints;
    std::vector<PeriodicEndpoint> periodic_endpoints;
};

struct RuleFinding {
    std::string name;
    std::string severity;
    int score{};
    std::string explanation;
};

struct AnalysisReport {
    std::chrono::system_clock::time_point generated_at;
    std::uint32_t target_pid{};
    std::string process_name;

    NetworkFeatures features;
    std::vector<RuleFinding> findings;

    int local_risk_score{};
    std::string local_verdict;

    std::string ai_assessment_json;
};
