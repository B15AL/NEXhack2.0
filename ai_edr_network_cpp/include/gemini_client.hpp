#pragma once

#include <string>

#include "models.hpp"

class GeminiClient {
public:
    // Creates a compact, structured analysis request.
    // HTTP/TLS transport is intentionally kept separate from the collector.
    static std::string build_analysis_payload(const AnalysisReport& report);

    // Integration point for a real Gemini API client.
    // Returns an empty string if no integration is configured.
    static std::string analyze(const AnalysisReport& report);
};
