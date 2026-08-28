#pragma once

#include <string>
#include "models.hpp"

std::string raw_report_to_json(
    const RawNetworkReport& report
);

bool write_raw_report(
    const RawNetworkReport& report,
    const std::string& directory,
    std::string& output_path
);
