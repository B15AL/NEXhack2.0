#include "collector.hpp"
#include "config.hpp"
#include "gemini_client.hpp"
#include "models.hpp"
#include "report.hpp"
#include "rules.hpp"

#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>

namespace {
    void print_usage(const char* program) {
        std::cout
            << "Usage:\n"
            << "  " << program
            << " --pid <PID> [--duration <seconds>] [--config <path>] [--no-ai]\n";
    }
}

int main(int argc, char* argv[]) {
    std::uint32_t pid = 0;
    int duration = -1;
    std::string config_path = "config/default.json";
    bool use_ai = true;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--pid" && i + 1 < argc) {
            pid = static_cast<std::uint32_t>(
                std::stoul(argv[++i])
            );
        } else if (arg == "--duration" && i + 1 < argc) {
            duration = std::stoi(argv[++i]);
        } else if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--no-ai") {
            use_ai = false;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (pid == 0) {
        std::cerr << "--pid is required.\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        const AppConfig config = load_config(config_path);

        if (duration <= 0) {
            duration = config.default_duration_seconds;
        }

        // The collector API needs a process name for report correlation.
        // The current MVP uses the PID as a fallback label.
        const std::string process_name =
            "pid_" + std::to_string(pid);

        std::cout
            << "Collecting network metadata for PID " << pid
            << " for " << duration << " seconds...\n";

        const auto events = NetworkCollector::collect(
            pid,
            process_name,
            duration,
            config.sample_interval_seconds
        );

        const NetworkFeatures features =
            extract_features(events, config);

        auto [score, verdict, findings] =
            evaluate_rules(features);

        AnalysisReport report;
        report.generated_at = std::chrono::system_clock::now();
        report.target_pid = pid;
        report.process_name = process_name;
        report.features = features;
        report.findings = findings;
        report.local_risk_score = score;
        report.local_verdict = verdict;

        if (use_ai) {
            report.ai_assessment_json =
                GeminiClient::analyze(report);
        }

        std::string output_path;

        if (!write_report(
                report,
                config.report_directory,
                output_path
            )) {
            std::cerr << "Failed to write report.\n";
            return 1;
        }

        std::cout << "\n--- Analysis complete ---\n";
        std::cout << "Observations: " << features.total_observations << "\n";
        std::cout << "Unique remote IPs: "
                  << features.unique_remote_ips << "\n";
        std::cout << "Repeated endpoints: "
                  << features.repeated_endpoints.size() << "\n";
        std::cout << "Periodic endpoints: "
                  << features.periodic_endpoints.size() << "\n";
        std::cout << "Local risk score: "
                  << report.local_risk_score << "/100\n";
        std::cout << "Local verdict: "
                  << report.local_verdict << "\n";
        std::cout << "Report: " << output_path << "\n";

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
