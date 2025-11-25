#include "runtime/options.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <unistd.h>

namespace {

std::string ensure_trailing_slash(const std::string& path) {
    if (path.empty() || path.back() == '/') {
        return path;
    }
    return path + "/";
}

std::unique_ptr<std::ofstream> g_log_stream;

} // namespace

GlobalOptions g_global_options;
const std::string RUNTIME_VERSION = "0.1.0";

bool configure_log_destination(const std::string& path) {
    std::unique_ptr<std::ofstream> stream(new std::ofstream(path, std::ios::app));
    if (!stream || !(*stream)) {
        std::cerr << "Failed to open log file: " << path << std::endl;
        return false;
    }
    g_log_stream = std::move(stream);
    // DO NOT redirect std::cerr buffer - causes segfault on program exit
    // when global destructors run in undefined order
    // std::cerr.rdbuf(g_log_stream->rdbuf());
    return true;
}

void log_debug(const std::string& message) {
    if (g_global_options.debug) {
        if (g_log_stream && g_log_stream->is_open()) {
            (*g_log_stream) << "[debug] " << message << std::endl;
        } else {
            std::cerr << "[debug] " << message << std::endl;
        }
    }
}

std::string state_base_path() {
    return ensure_trailing_slash(g_global_options.root_path);
}

std::string fallback_state_root() {
    return "/tmp/mruntime-" + std::to_string(geteuid());
}

std::string default_state_root() {
    if (geteuid() == 0) {
        return "/run/mruntime";
    }
    const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR");
    if (runtime_dir && runtime_dir[0] != '\0') {
        return ensure_trailing_slash(runtime_dir) + "mruntime";
    }
    return fallback_state_root();
}
