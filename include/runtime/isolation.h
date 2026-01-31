#pragma once

#include <string>
#include <sys/types.h>

#include "runtime/config.h"

unsigned long cpu_shares_to_weight(long long shares);

void setup_cgroups(pid_t pid,
                   const std::string& id,
                   const LinuxConfig& linux_config,
                   std::string& out_relative_path);

void cleanup_cgroups(const std::string& id, const std::string& relative_path_hint);

bool configure_user_namespace(pid_t pid,
                              bool creates_new_userns,
                              const std::vector<LinuxIDMapping>& uid_mappings,
                              const std::vector<LinuxIDMapping>& gid_mappings);
