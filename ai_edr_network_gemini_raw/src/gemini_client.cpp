#include "gemini_client.hpp"
#include "raw_report.hpp"

#include <curl/curl.h>

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

namespace {

size_t write_callback(
    void* contents,
    size_t size,
    size_t nmemb,
    void* userp
) {
    const size_t total = size * nmemb;

    auto* response =
        static_cast<std::string*>(userp);

    response->append(
        static_cast<char*>(contents),
        total);

    return total;
}

std::string escape_json(
    const std::string& input
) {
    std::ostringstream out;

    for (char c : input) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << c;
        }
    }

    return out.str();
}

std::string extract_text(
    const std::string& response
) {
    const std::string marker = "\"text\"";

    std::size_t position =
        response.find(marker);

    while (position != std::string::npos) {
        position =
            response.find(':', position);

        if (position == std::string::npos)
            return {};

        ++position;

        while (
            position < response.size() &&
            (response[position] == ' ' ||
             response[position] == '\t')
        ) {
            ++position;
        }

        if (
            position < response.size() &&
            response[position] == '"'
        ) {
            ++position;

            std::string result;
            bool escaped = false;

            for (; position < response.size(); ++position) {
                const char c = response[position];

                if (escaped) {
                    switch (c) {
                        case 'n': result += '\n'; break;
                        case 'r': result += '\r'; break;
                        case 't': result += '\t'; break;
                        case '"': result += '"'; break;
                        case '\\': result += '\\'; break;
                        default: result += c; break;
                    }

                    escaped = false;
                    continue;
                }

                if (c == '\\') {
                    escaped = true;
                    continue;
                }

                if (c == '"')
                    return result;

                result += c;
            }
        }

        position =
            response.find(marker, position);
    }

    return {};
}

std::string build_prompt(
    const RawNetworkReport& report
) {
    const std::string raw =
        raw_report_to_json(report);

    std::ostringstream prompt;

    prompt << R"(You are the network-behaviour analyst for a defensive EDR sandbox.

You will receive RAW network telemetry generated while a process was running.

Your task is to interpret the observed network behaviour and assess whether it is
consistent with malware.

Analyze the telemetry carefully, including:
- remote IP addresses
- remote ports
- protocols
- timestamps and communication frequency
- repeated destinations
- periodic communication / possible beaconing
- destination diversity
- connection states
- unusual or unexpected network behaviour

Important rules:
1. Network behaviour alone is NOT definitive proof of malware.
2. Do not call a process malicious merely because it uses HTTPS, an unusual port,
   or a public/cloud IP.
3. Separate direct observations from hypotheses.
4. Benign software can poll servers periodically.
5. Use "inconclusive" when the telemetry does not provide enough evidence.
6. Do not invent reputation information about an IP/domain unless it is present
   in the supplied telemetry.
7. Do not claim packet contents were inspected; this report contains connection
   metadata only.

Return ONLY valid JSON. Do not wrap it in Markdown.

Use exactly this structure:

{
  "verdict": "malicious|suspicious|benign|inconclusive",
  "confidence": 0.0,
  "reasoning": [
    "evidence-based explanation"
  ],
  "network_indicators": [
    "observed indicator"
  ],
  "possible_behaviors": [
    "possible behavior or null"
  ],
  "recommendation": "allow|monitor|isolate_and_investigate"
}

Confidence must be between 0.0 and 1.0.

RAW NETWORK REPORT:
)";

    prompt << raw;

    return prompt.str();
}

}

std::string GeminiClient::build_analysis_payload(
    const RawNetworkReport& report
) {
    const std::string prompt =
        build_prompt(report);

    std::ostringstream payload;

    payload << "{"
            << "\"contents\":["
            << "{"
            << "\"parts\":["
            << "{"
            << "\"text\":\""
            << escape_json(prompt)
            << "\""
            << "}"
            << "]"
            << "}"
            << "]"
            << "}";

    return payload.str();
}

std::string GeminiClient::analyze(
    const RawNetworkReport& report
) {
    const char* key =
        std::getenv("GEMINI_API_KEY");

    if (key == nullptr ||
        std::string(key).empty()) {

        std::cerr
            << "[Gemini] GEMINI_API_KEY is not set."
            << std::endl;

        return {};
    }

    const char* configured_model =
        std::getenv("GEMINI_MODEL");

    const std::string model =
        (configured_model &&
         std::string(configured_model).size() > 0)
            ? configured_model
            : "gemini-3.6-flash";

    const std::string url =
        "https://generativelanguage.googleapis.com/"
        "v1beta/models/" +
        model +
        ":generateContent";

    const std::string payload =
        build_analysis_payload(report);

    CURL* curl =
        curl_easy_init();

    if (!curl) {
        std::cerr
            << "[Gemini] Could not initialize libcurl."
            << std::endl;

        return {};
    }

    std::string response;

    struct curl_slist* headers = nullptr;

    headers = curl_slist_append(
        headers,
        "Content-Type: application/json");

    const std::string key_header =
        std::string("x-goog-api-key: ") + key;

    headers = curl_slist_append(
        headers,
        key_header.c_str());

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url.c_str());

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers);

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L);

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        payload.c_str());

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDSIZE,
        static_cast<long>(payload.size()));

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback);

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response);

    curl_easy_setopt(
        curl,
        CURLOPT_CONNECTTIMEOUT,
        10L);

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        45L);

    const CURLcode result =
        curl_easy_perform(curl);

    long status = 0;

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        std::cerr
            << "[Gemini] Request failed: "
            << curl_easy_strerror(result)
            << std::endl;

        return {};
    }

    if (status < 200 || status >= 300) {
        std::cerr
            << "[Gemini] HTTP status: "
            << status
            << std::endl;

        std::cerr << response << std::endl;

        return {};
    }

    const std::string text =
        extract_text(response);

    if (text.empty()) {
        std::cerr
            << "[Gemini] Empty/invalid model text."
            << std::endl;

        return {};
    }

    return text;
}
