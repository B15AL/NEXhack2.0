#include "raw_report.hpp"

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
            default: out << c;
        }
    }

    return out.str();
}

std::string time_string(
    std::chrono::system_clock::time_point point
) {
    const std::time_t t =
        std::chrono::system_clock::to_time_t(point);

    std::tm tm{};

#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif

    std::ostringstream out;

    out << std::put_time(
        &tm,
        "%Y-%m-%dT%H:%M:%SZ");

    return out.str();
}
}

std::string raw_report_to_json(
    const RawNetworkReport& report
) {
    std::ostringstream out;

    out << "{\n";

    out << "  \"generated_at\": \""
        << time_string(report.generated_at)
        << "\",\n";

    out << "  \"process\": {\n";

    out << "    \"pid\": "
        << report.target_pid
        << ",\n";

    out << "    \"name\": \""
        << escape_json(report.process_name)
        << "\"\n";

    out << "  },\n";

    out << "  \"observation_duration_seconds\": "
        << report.observation_duration_seconds
        << ",\n";

    out << "  \"observations\": [\n";

    for (std::size_t i = 0;
         i < report.observations.size();
         ++i) {

        const auto& e =
            report.observations[i];

        out << "    {\n";

        out << "      \"timestamp\": \""
            << time_string(e.timestamp)
            << "\",\n";

        out << "      \"pid\": "
            << e.pid
            << ",\n";

        out << "      \"process_name\": \""
            << escape_json(e.process_name)
            << "\",\n";

        out << "      \"local_ip\": \""
            << escape_json(e.local_ip)
            << "\",\n";

        out << "      \"local_port\": "
            << e.local_port
            << ",\n";

        out << "      \"remote_ip\": \""
            << escape_json(e.remote_ip)
            << "\",\n";

        out << "      \"remote_port\": "
            << e.remote_port
            << ",\n";

        out << "      \"protocol\": \""
            << escape_json(e.protocol)
            << "\",\n";

        out << "      \"state\": \""
            << escape_json(e.state)
            << "\"\n";

        out << "    }";

        if (i + 1 < report.observations.size())
            out << ",";

        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";

    return out.str();
}

bool write_raw_report(
    const RawNetworkReport& report,
    const std::string& directory,
    std::string& output_path
) {
    namespace fs = std::filesystem;

    std::error_code ec;
    fs::create_directories(directory, ec);

    if (ec)
        return false;

    const std::time_t t =
        std::chrono::system_clock::to_time_t(
            report.generated_at);

    std::tm tm{};

#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    std::ostringstream filename;

    filename << "network_report_"
             << std::put_time(
                    &tm,
                    "%Y%m%d_%H%M%S")
             << ".json";

    const fs::path path =
        fs::path(directory) / filename.str();

    std::ofstream file(path);

    if (!file)
        return false;

    file << raw_report_to_json(report);

    output_path = path.string();

    return true;
}
