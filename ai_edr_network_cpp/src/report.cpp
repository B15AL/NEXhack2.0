#include "report.hpp"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {
    std::string escape_json(const std::string& value) {
        std::ostringstream out;

        for (char c : value) {
            switch (c) {
                case '"': out << "\\\""; break;
                case '\\': out << "\\\\"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default: out << c; break;
            }
        }

        return out.str();
    }

    std::string iso_time(
        const std::chrono::system_clock::time_point& point
    ) {
        const std::time_t time = std::chrono::system_clock::to_time_t(point);

        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &time);
#else
        gmtime_r(&time, &tm);
#endif

        std::ostringstream out;
        out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        return out.str();
    }
}

std::string report_to_json(const AnalysisReport& report) {
    std::ostringstream out;

    out << "{\n";
    out << "  \"generated_at\": \"" << iso_time(report.generated_at) << "\",\n";
    out << "  \"target_pid\": " << report.target_pid << ",\n";
    out << "  \"process_name\": \"" << escape_json(report.process_name) << "\",\n";

    out << "  \"network_features\": {\n";
    out << "    \"total_observations\": " << report.features.total_observations << ",\n";
    out << "    \"unique_remote_ips\": " << report.features.unique_remote_ips << ",\n";
    out << "    \"unique_remote_ports\": " << report.features.unique_remote_ports << ",\n";
    out << "    \"tcp_observations\": " << report.features.tcp_observations << ",\n";
    out << "    \"udp_observations\": " << report.features.udp_observations << ",\n";

    out << "    \"repeated_endpoints\": [";
    for (std::size_t i = 0; i < report.features.repeated_endpoints.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << escape_json(report.features.repeated_endpoints[i]) << "\"";
    }
    out << "],\n";

    out << "    \"periodic_endpoints\": [\n";
    for (std::size_t i = 0; i < report.features.periodic_endpoints.size(); ++i) {
        const auto& endpoint = report.features.periodic_endpoints[i];

        out << "      {\n";
        out << "        \"endpoint\": \"" << escape_json(endpoint.endpoint) << "\",\n";
        out << "        \"observations\": " << endpoint.observations << ",\n";
        out << "        \"mean_interval_seconds\": " << endpoint.mean_interval_seconds << ",\n";
        out << "        \"relative_interval_std\": " << endpoint.relative_interval_std << "\n";
        out << "      }";

        if (i + 1 < report.features.periodic_endpoints.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "    ]\n";
    out << "  },\n";

    out << "  \"rule_findings\": [\n";
    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const auto& finding = report.findings[i];

        out << "    {\n";
        out << "      \"name\": \"" << escape_json(finding.name) << "\",\n";
        out << "      \"severity\": \"" << escape_json(finding.severity) << "\",\n";
        out << "      \"score\": " << finding.score << ",\n";
        out << "      \"explanation\": \"" << escape_json(finding.explanation) << "\"\n";
        out << "    }";

        if (i + 1 < report.findings.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"local_risk_score\": " << report.local_risk_score << ",\n";
    out << "  \"local_verdict\": \"" << escape_json(report.local_verdict) << "\"";

    if (!report.ai_assessment_json.empty()) {
        out << ",\n  \"ai_assessment\": "
            << report.ai_assessment_json;
    }

    out << "\n}\n";

    return out.str();
}

bool write_report(
    const AnalysisReport& report,
    const std::string& directory,
    std::string& output_path
) {
    namespace fs = std::filesystem;

    std::error_code ec;
    fs::create_directories(directory, ec);

    if (ec) {
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif

    std::ostringstream filename;
    filename << "report_" << std::put_time(&tm, "%Y%m%d_%H%M%S")
             << ".json";

    const fs::path path = fs::path(directory) / filename.str();

    std::ofstream file(path);
    if (!file) {
        return false;
    }

    file << report_to_json(report);
    output_path = path.string();

    return true;
}
