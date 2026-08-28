#include "rules.hpp"

#include <algorithm>

std::tuple<int, std::string, std::vector<RuleFinding>>
evaluate_rules(const NetworkFeatures& features) {
    std::vector<RuleFinding> findings;
    int score = 0;

    if (!features.periodic_endpoints.empty()) {
        const int points = std::min(
            35,
            static_cast<int>(features.periodic_endpoints.size()) * 10
        );

        score += points;

        findings.push_back(
            RuleFinding{
                "Possible periodic outbound activity",
                "medium",
                points,
                "One or more remote endpoints were observed at relatively "
                "regular intervals. This may be consistent with automated "
                "polling or beacon-like behaviour, but benign software can "
                "also show this pattern."
            }
        );
    }

    if (!features.repeated_endpoints.empty()) {
        const int points = std::min(
            20,
            static_cast<int>(features.repeated_endpoints.size()) * 5
        );

        score += points;

        findings.push_back(
            RuleFinding{
                "Repeated remote endpoint",
                "low",
                points,
                "The process repeatedly communicated with the same remote "
                "endpoint during the observation window."
            }
        );
    }

    if (features.unique_remote_ips > 20) {
        score += 10;

        findings.push_back(
            RuleFinding{
                "High destination diversity",
                "low",
                10,
                "The process contacted a large number of distinct remote "
                "IP addresses during the observation period."
            }
        );
    }

    score = std::min(score, 100);

    std::string verdict;

    if (score >= 70) {
        verdict = "HIGH";
    } else if (score >= 40) {
        verdict = "MEDIUM";
    } else if (score > 0) {
        verdict = "LOW";
    } else {
        verdict = "UNKNOWN";
    }

    return {score, verdict, findings};
}
