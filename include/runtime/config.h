#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "json.hpp"

using json = nlohmann::json;

struct ProcessConfig {
    bool terminal = false;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd = "/";
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::vector<uint32_t> additional_gids;
};

struct RootConfig {
    std::string path;
    bool readonly = false;
};

struct LinuxNamespaceConfig {
    std::string type;
    std::string path;
};

struct LinuxIDMapping {
    uint32_t host_id = 0;
    uint32_t container_id = 0;
    uint32_t size = 0;
};

struct LinuxResourcesConfig {
    long long memory_limit = 0;
    long long cpu_shares = 0;
};

struct MountConfig {
    std::string destination;
    std::string type;
    std::string source;
    std::vector<std::string> options;
};

struct LinuxConfig {
    std::vector<LinuxNamespaceConfig> namespaces;
    LinuxResourcesConfig resources;
    std::vector<LinuxIDMapping> uid_mappings;
    std::vector<LinuxIDMapping> gid_mappings;
    std::vector<std::string> masked_paths;
    std::vector<std::string> readonly_paths;
    std::string rootfs_propagation;
    std::string cgroups_path;
};

struct HookConfig {
    std::string path;
    std::vector<std::string> args;
    std::vector<std::string> env;
    int timeout = 0;
};

struct HooksConfig {
    std::vector<HookConfig> create_runtime;
    std::vector<HookConfig> create_container;
    std::vector<HookConfig> start_container;
    std::vector<HookConfig> prestart;
    std::vector<HookConfig> poststart;
    std::vector<HookConfig> poststop;
};

struct OCIConfig {
    std::string ociVersion;
    RootConfig root;
    ProcessConfig process;
    std::string hostname;
    LinuxConfig linux;
    std::vector<MountConfig> mounts;
    std::map<std::string, std::string> annotations;
    HooksConfig hooks;
};

OCIConfig load_config(const std::string& bundle_path);
std::string resolve_absolute_path(const std::string& path);

void from_json(const json& j, ProcessConfig& p);
void from_json(const json& j, RootConfig& r);
void from_json(const json& j, LinuxNamespaceConfig& ns);
void from_json(const json& j, LinuxIDMapping& map);
void from_json(const json& j, LinuxResourcesConfig& res);
void from_json(const json& j, LinuxConfig& l);
void from_json(const json& j, MountConfig& m);
void from_json(const json& j, HookConfig& hook);
void from_json(const json& j, HooksConfig& hooks);
void from_json(const json& j, OCIConfig& c);
