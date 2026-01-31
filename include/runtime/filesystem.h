#pragma once

#include <string>
#include <sys/stat.h>
#include <vector>

struct ParsedMountOptions {
    unsigned long flags = 0;
    unsigned long propagation = 0;
    bool has_propagation = false;
    bool bind_readonly = false;
    std::string data;
};

bool ensure_directory(const std::string& path, mode_t mode = 0755);
bool ensure_parent_directory(const std::string& path);
bool ensure_file(const std::string& path, mode_t mode = 0644);
bool ensure_runtime_root_directory();

std::string container_absolute_path(const std::string& rootfs, const std::string& path);
unsigned long propagation_flag_from_string(const std::string& propagation);
bool apply_mount_propagation(const std::string& path, const std::string& propagation);
ParsedMountOptions parse_mount_options(const std::vector<std::string>& options);
std::string join_strings(const std::vector<std::string>& parts, const char* delimiter = ",");
