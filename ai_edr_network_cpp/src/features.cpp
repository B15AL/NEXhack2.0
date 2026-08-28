#include "features.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <set>
#include <unordered_map>

namespace {
    std::string endpoint_key(const ConnectionEvent& event) {
        if (event.remote_ip.empty()) {
            return {};
        }
        return event.remote_ip + ":" + std::to_string(event.remote_port);
    }

    double seconds_between(
        const std::chrono::system_clock::time_point& a,
        const std::chrono::system_clock::time_point& b
    ) {
        return std::chrono::duration<double>(b - a).count();
    }

    double mean(const std::vector<double>& values) {
        if (values.empty()) return 0.0;

        const double sum = std::accumulate(
            values.begin(), values.end(), 0.0
        );
        return sum / static_cast<double>(values.size());
    }

    double population_stddev(
        const std::vector<double>& values,
        double average
    ) {
        if (values.empty()) return 0.0;

        double squared_sum = 0.0;
        for (double value : values) {
            const double diff = value - average;
            squared_sum += diff * diff;
        }

        return std::sqrt(
            squared_sum / static_cast<double>(values.size())
        );
    }
}

NetworkFeatures extract_features(
    const std::vector<ConnectionEvent>& events,
    const AppConfig& config
) {
    NetworkFeatures features;
    features.total_observations = events.size();

    std::set<std::string> ips;
    std::set<std::uint16_t> ports;

    std::unordered_map<
        std::string,
        std::vector<std::chrono::system_clock::time_point>
    > endpoint_times;

    for (const auto& event : events) {
        if (!event.remote_ip.empty()) {
            ips.insert(event.remote_ip);
            ports.insert(event.remote_port);

            endpoint_times[endpoint_key(event)].push_back(
                event.timestamp
            );
        }

        if (event.protocol == "TCP") {
            ++features.tcp_observations;
        } else if (event.protocol == "UDP") {
            ++features.udp_observations;
        }
    }

    features.unique_remote_ips = ips.size();
    features.unique_remote_ports = ports.size();

    for (auto& [endpoint, times] : endpoint_times) {
        if (static_cast<int>(times.size()) >=
            config.repeated_endpoint_threshold) {
            features.repeated_endpoints.push_back(endpoint);
        }

        if (static_cast<int>(times.size()) <
            config.beacon_min_observations) {
            continue;
        }

        std::sort(times.begin(), times.end());

        std::vector<double> intervals;
        for (std::size_t i = 1; i < times.size(); ++i) {
            const double interval = seconds_between(
                times[i - 1], times[i]
            );

            if (interval > 0.0) {
                intervals.push_back(interval);
            }
        }

        if (intervals.size() < 2) {
            continue;
        }

        const double avg = mean(intervals);

        if (avg <= 0.0) {
            continue;
        }

        const double stddev = population_stddev(intervals, avg);
        const double relative_std = stddev / avg;

        if (relative_std <=
            config.beacon_max_relative_interval_std) {
            features.periodic_endpoints.push_back(
                PeriodicEndpoint{
                    endpoint,
                    times.size(),
                    avg,
                    relative_std
                }
            );
        }
    }

    return features;
}
