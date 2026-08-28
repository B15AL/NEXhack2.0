#include "collector.hpp"
#include "gemini_client.hpp"
#include "raw_report.hpp"

#include <chrono>
#include <fstream>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<ConnectionEvent> demo_events() {
    const auto start =
        std::chrono::system_clock::now();

    std::vector<ConnectionEvent> events;

    // Synthetic telemetry only. No network traffic is generated.
    for (int i = 0; i < 6; ++i) {
        ConnectionEvent e;

        e.timestamp =
            start +
            std::chrono::seconds(i * 10);

        e.pid = 99999;
        e.process_name = "demo_process";

        e.local_ip = "192.0.2.10";
        e.local_port =
            static_cast<std::uint16_t>(50000 + i);

        e.remote_ip = "203.0.113.10";
        e.remote_port = 443;

        e.protocol = "TCP";
        e.state = "ESTABLISHED";

        events.push_back(e);
    }

    return events;
}

void usage(const char* program) {
    std::cout
        << "Usage:\n"
        << "  " << program << " --demo\n"
        << "  " << program << " --demo --ai\n"
        << "  " << program
        << " --pid <PID> [--duration <seconds>] [--ai]\n"
        << "  " << program
        << " --pid <PID> [--duration <seconds>] --no-ai\n";
}

}

int main(int argc, char* argv[]) {
    bool demo = false;
    bool ai = false;
    bool no_ai = false;

    std::uint32_t pid = 0;
    int duration = 30;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--demo") {
            demo = true;
        } else if (arg == "--ai") {
            ai = true;
        } else if (arg == "--no-ai") {
            no_ai = true;
        } else if (
            arg == "--pid" &&
            i + 1 < argc
        ) {
            pid =
                static_cast<std::uint32_t>(
                    std::stoul(argv[++i]));
        } else if (
            arg == "--duration" &&
            i + 1 < argc
        ) {
            duration =
                std::stoi(argv[++i]);
        } else if (
            arg == "--help" ||
            arg == "-h"
        ) {
            usage(argv[0]);
            return 0;
        } else {
            std::cerr
                << "Unknown argument: "
                << arg << "\n";

            usage(argv[0]);
            return 1;
        }
    }

    if (demo && pid != 0) {
        std::cerr
            << "Use either --demo or --pid, not both.\n";
        return 1;
    }

    if (!demo && pid == 0) {
        usage(argv[0]);
        return 1;
    }

    if (ai && no_ai) {
        std::cerr
            << "Use either --ai or --no-ai, not both.\n";
        return 1;
    }

    std::vector<ConnectionEvent> observations;
    std::string process_name;

    if (demo) {
        std::cout
            << "Running synthetic network telemetry demo.\n";

        observations = demo_events();

        pid = 99999;
        process_name = "demo_process";

    } else {
        process_name =
            "pid_" + std::to_string(pid);

        std::cout
            << "Collecting network metadata for PID "
            << pid
            << " for "
            << duration
            << " seconds...\n";

        try {
            observations =
                NetworkCollector::collect(
                    pid,
                    process_name,
                    duration,
                    1);
        } catch (const std::exception& ex) {
            std::cerr
                << "Collector error: "
                << ex.what()
                << "\n";

            return 1;
        }
    }

    RawNetworkReport report;

    report.generated_at =
        std::chrono::system_clock::now();

    report.target_pid = pid;
    report.process_name = process_name;
    report.observation_duration_seconds =
        duration;
    report.observations =
        observations;

    std::string report_path;

    if (!write_raw_report(
            report,
            "data/reports",
            report_path)) {

        std::cerr
            << "Could not write raw network report.\n";

        return 1;
    }

    std::cout
        << "\n=== Raw Network Report ===\n"
        << "Observations: "
        << observations.size()
        << "\n"
        << "Report: "
        << report_path
        << "\n";

    if (no_ai)
        ai = false;

    if (ai) {
        std::cout
            << "\n[AI] Sending raw network report to Gemini...\n";

        const std::string assessment =
            GeminiClient::analyze(report);

        if (assessment.empty()) {
            std::cerr
                << "[AI] No assessment received.\n";

            return 2;
        }

        std::cout
            << "[AI] Assessment received:\n"
            << assessment
            << "\n";

        // Write a second report containing both raw telemetry
        // and the model output without exposing the API key.
        std::string ai_path =
            report_path;

        const auto dot =
            ai_path.rfind(".json");

        if (dot != std::string::npos)
            ai_path.insert(dot, "_ai");

        std::ofstream out(ai_path);

        if (out) {
            out
                << "{\n"
                << "  \"raw_network_report\": "
                << raw_report_to_json(report)
                << ",\n"
                << "  \"ai_assessment\": "
                << assessment
                << "\n"
                << "}\n";

            std::cout
                << "[AI] Combined report: "
                << ai_path
                << "\n";
        }
    }

    return 0;
}
