#pragma once

#include <memory>
#include <string>

struct GlobalOptions {
    bool debug = false;
    bool systemd_cgroup = false;
    std::string log_path;
    std::string log_format = "text";
    std::string root_path;
};

extern GlobalOptions g_global_options;
extern const std::string RUNTIME_VERSION;

bool configure_log_destination(const std::string& path);
void log_debug(const std::string& message);
std::string state_base_path();
std::string fallback_state_root();
std::string default_state_root();
