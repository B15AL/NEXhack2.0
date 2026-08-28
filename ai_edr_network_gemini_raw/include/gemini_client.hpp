#pragma once

#include <string>
#include "models.hpp"

class GeminiClient {
public:
    static std::string build_analysis_payload(
        const RawNetworkReport& report
    );

    static std::string analyze(
        const RawNetworkReport& report
    );
};
