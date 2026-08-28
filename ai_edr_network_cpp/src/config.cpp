#include "config.hpp"

#include <fstream>
#include <regex>
#include <sstream>

namespace {
    int extract_int(const std::string& text, const std::string& key, int fallback) {
        const std::regex pattern("\"" + key + R"("\s*:\s*([0-9]+))");
        std::smatch match;
        if (std::regex_search(text, match, pattern)) {
            return std::stoi(match[1].str());
        }
        return fallback;
    }

    double extract_double(const std::string& text, const std::string& key, double fallback) {
        const std::regex pattern("\"" + key + R"("\s*:\s*([0-9]+(?:\.[0-9]+)?))");
        std::smatch match;
        if (std::regex_search(text, match, pattern)) {
            return std::stod(match[1].str());
        }
        return fallback;
    }

    std::string extract_string(const std::string& text, const std::string& key, const std::string& fallback) {
        const std::regex pattern("\"" + key + R"("\s*:\s*"([^"]+)")");
        std::smatch match;
        if (std::regex_search(text, match, pattern)) {
            return match[1].str();
        }
        return fallback;
    }
}

AppConfig load_config(const std::string& path) {
    AppConfig config;

    std::ifstream file(path);
    if (!file) {
        return config;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    const std::string text = buffer.str();

    config.sample_interval_seconds =
        extract_int(text, "sample_interval_seconds", config.sample_interval_seconds);
    config.default_duration_seconds =
        extract_int(text, "default_duration_seconds", config.default_duration_seconds);

    config.beacon_min_observations =
        extract_int(text, "beacon_min_observations", config.beacon_min_observations);
    config.beacon_max_relative_interval_std =
        extract_double(text, "beacon_max_relative_interval_std",
                       config.beacon_max_relative_interval_std);
    config.repeated_endpoint_threshold =
        extract_int(text, "repeated_endpoint_threshold",
                    config.repeated_endpoint_threshold);

    config.report_directory =
        extract_string(text, "report_directory", config.report_directory);

    return config;
}
