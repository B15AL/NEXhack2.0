#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "models.hpp"

class NetworkCollector {
public:
    static std::vector<ConnectionEvent> collect(
        std::uint32_t pid,
        const std::string& process_name,
        int duration_seconds,
        int interval_seconds = 1
    );
};
