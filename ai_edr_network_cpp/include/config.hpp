#pragma once

#include <string>

struct AppConfig {
    int sample_interval_seconds{1};
    int default_duration_seconds{60};

    int beacon_min_observations{4};
    double beacon_max_relative_interval_std{0.20};
    int repeated_endpoint_threshold{5};

    std::string report_directory{"data/reports"};
};

AppConfig load_config(const std::string& path);
