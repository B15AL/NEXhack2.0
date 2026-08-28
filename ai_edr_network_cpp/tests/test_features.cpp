#include "config.hpp"
#include "features.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <vector>

int main() {
    AppConfig config;
    config.beacon_min_observations = 4;
    config.beacon_max_relative_interval_std = 0.20;
    config.repeated_endpoint_threshold = 5;

    const auto start = std::chrono::system_clock::now();

    std::vector<ConnectionEvent> events;

    for (int i = 0; i < 5; ++i) {
        ConnectionEvent event;
        event.timestamp =
            start + std::chrono::seconds(i * 10);
        event.pid = 1;
        event.process_name = "test.exe";
        event.remote_ip = "203.0.113.10";
        event.remote_port = 443;
        event.protocol = "TCP";

        events.push_back(event);
    }

    const NetworkFeatures features =
        extract_features(events, config);

    assert(features.repeated_endpoints.size() == 1);
    assert(features.repeated_endpoints[0] ==
           "203.0.113.10:443");

    assert(features.periodic_endpoints.size() == 1);
    assert(features.periodic_endpoints[0].endpoint ==
           "203.0.113.10:443");

    std::cout << "Feature tests passed.\n";
    return 0;
}
