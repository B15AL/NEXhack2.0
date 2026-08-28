#include "gemini_client.hpp"

#include "report.hpp"

#include <cstdlib>
#include <sstream>

std::string GeminiClient::build_analysis_payload(
    const AnalysisReport& report
) {
    // Reuse the report serializer as a compact starting point.
    // A production version may construct a smaller provider-specific payload.
    return report_to_json(report);
}

std::string GeminiClient::analyze(
    const AnalysisReport& report
) {
    const char* api_key = std::getenv("GEMINI_API_KEY");

    if (api_key == nullptr || std::string(api_key).empty()) {
        return {};
    }

    /*
        Integration point:

        1. Use a proper HTTPS client such as libcurl.
        2. Read GEMINI_MODEL from the environment.
        3. Send build_analysis_payload(report) as summarized evidence.
        4. Request strict JSON output.
        5. Return the validated JSON response.

        The collector and detection pipeline deliberately remain independent
        of external AI API transport.
    */

    (void)report;
    return {};
}
