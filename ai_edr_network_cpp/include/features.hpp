#pragma once

#include <vector>

#include "config.hpp"
#include "models.hpp"

NetworkFeatures extract_features(
    const std::vector<ConnectionEvent>& events,
    const AppConfig& config
);
