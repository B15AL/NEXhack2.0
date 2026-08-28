#pragma once

#include <tuple>
#include <vector>

#include "models.hpp"

std::tuple<int, std::string, std::vector<RuleFinding>>
evaluate_rules(const NetworkFeatures& features);
