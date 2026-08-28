#pragma once

#include <string>

#include "models.hpp"

std::string report_to_json(const AnalysisReport& report);

bool write_report(
    const AnalysisReport& report,
    const std::string& directory,
    std::string& output_path
);
