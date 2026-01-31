#pragma once

#include <string>
#include <vector>

#include "runtime/config.h"
#include "runtime/state.h"

bool run_hook_sequence(const std::vector<HookConfig>& hooks,
                       ContainerState& state,
                       const std::string& hook_type,
                       bool enforce_once = true);
