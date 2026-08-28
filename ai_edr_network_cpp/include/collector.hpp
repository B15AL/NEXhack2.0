#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "models.hpp"

class NetworkCollector {
public:
    // Collect process-owned IPv4 TCP/UDP endpoint observations for a
    // controlled Windows lab environment.
    static std::vector<ConnectionEvent> collect(
        std::uint32_t pid,
        const std::string& process_name,
        int duration_seconds,
        int interval_seconds
    );
};
