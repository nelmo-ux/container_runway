#include "runtime/config.h"

#include <cstdlib>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "json.hpp"

using json = nlohmann::json;

void from_json(const json& j, ProcessConfig& p) {
    j.at("args").get_to(p.args);
    if (p.args.empty()) {
        throw std::runtime_error("process.args must not be empty");
    }
    if (j.contains("cwd")) {
        j.at("cwd").get_to(p.cwd);
    } else {
        p.cwd = "/";
    }
    if (j.contains("terminal")) {
        j.at("terminal").get_to(p.terminal);
    } else {
        p.terminal = false;
    }
    if (j.contains("env")) {
        j.at("env").get_to(p.env);
    }
    if (j.contains("user")) {
        const auto& user = j["user"];
        if (user.contains("uid")) {
            user.at("uid").get_to(p.uid);
        }
        if (user.contains("gid")) {
            user.at("gid").get_to(p.gid);
        }
        if (user.contains("additionalGids")) {
            user.at("additionalGids").get_to(p.additional_gids);
        }
    }
}

void from_json(const json& j, RootConfig& r) {
    j.at("path").get_to(r.path);
    if (j.contains("readonly")) {
        j.at("readonly").get_to(r.readonly);
    } else {
        r.readonly = false;
    }
}

void from_json(const json& j, LinuxNamespaceConfig& ns) {
    j.at("type").get_to(ns.type);
    if (j.contains("path")) {
        j.at("path").get_to(ns.path);
    }
}

void from_json(const json& j, LinuxIDMapping& map) {
    j.at("hostID").get_to(map.host_id);
    j.at("containerID").get_to(map.container_id);
    j.at("size").get_to(map.size);
}

void from_json(const json& j, LinuxResourcesConfig& res) {
    if (j.contains("memory") && j["memory"].contains("limit")) {
        j["memory"].at("limit").get_to(res.memory_limit);
    }
    if (j.contains("cpu") && j["cpu"].contains("shares")) {
        j["cpu"].at("shares").get_to(res.cpu_shares);
    }
}

void from_json(const json& j, LinuxConfig& l) {
    if (j.contains("namespaces")) {
        j.at("namespaces").get_to(l.namespaces);
    }
    if (j.contains("resources")) {
        j.at("resources").get_to(l.resources);
    }
    if (j.contains("uidMappings")) {
        j.at("uidMappings").get_to(l.uid_mappings);
    }
    if (j.contains("gidMappings")) {
        j.at("gidMappings").get_to(l.gid_mappings);
    }
    if (j.contains("maskedPaths")) {
        j.at("maskedPaths").get_to(l.masked_paths);
    }
    if (j.contains("readonlyPaths")) {
        j.at("readonlyPaths").get_to(l.readonly_paths);
    }
    if (j.contains("rootfsPropagation")) {
        j.at("rootfsPropagation").get_to(l.rootfs_propagation);
    }
    if (j.contains("cgroupsPath")) {
        j.at("cgroupsPath").get_to(l.cgroups_path);
    }
}

void from_json(const json& j, MountConfig& m) {
    j.at("destination").get_to(m.destination);
    if (j.contains("type")) {
        j.at("type").get_to(m.type);
    }
    if (j.contains("source")) {
        j.at("source").get_to(m.source);
    }
    if (j.contains("options")) {
        j.at("options").get_to(m.options);
    }
}

void from_json(const json& j, HookConfig& hook) {
    j.at("path").get_to(hook.path);
    if (j.contains("args")) {
        j.at("args").get_to(hook.args);
    }
    if (j.contains("env")) {
        j.at("env").get_to(hook.env);
    }
    if (j.contains("timeout")) {
        j.at("timeout").get_to(hook.timeout);
    } else {
        hook.timeout = 0;
    }
}

void from_json(const json& j, HooksConfig& hooks) {
    if (j.contains("createRuntime")) {
        j.at("createRuntime").get_to(hooks.create_runtime);
    }
    if (j.contains("createContainer")) {
        j.at("createContainer").get_to(hooks.create_container);
    }
    if (j.contains("startContainer")) {
        j.at("startContainer").get_to(hooks.start_container);
    }
    if (j.contains("prestart")) {
        j.at("prestart").get_to(hooks.prestart);
    }
    if (j.contains("poststart")) {
        j.at("poststart").get_to(hooks.poststart);
    }
    if (j.contains("poststop")) {
        j.at("poststop").get_to(hooks.poststop);
    }
}

void from_json(const json& j, OCIConfig& c) {
    j.at("ociVersion").get_to(c.ociVersion);
    j.at("root").get_to(c.root);
    j.at("process").get_to(c.process);
    if (j.contains("hostname")) {
        j.at("hostname").get_to(c.hostname);
    }
    if (j.contains("linux")) {
        j.at("linux").get_to(c.linux);
    }
    if (j.contains("mounts")) {
        j.at("mounts").get_to(c.mounts);
    }
    if (j.contains("annotations")) {
        j.at("annotations").get_to(c.annotations);
    }
    if (j.contains("hooks")) {
        j.at("hooks").get_to(c.hooks);
    }
}

OCIConfig load_config(const std::string& bundle_path) {
    std::string config_path = bundle_path + "/config.json";
    std::ifstream ifs(config_path);
    if (!ifs) {
        throw std::runtime_error("Failed to load config.json: " + config_path);
    }
    json j;
    ifs >> j;
    return j.get<OCIConfig>();
}

std::string resolve_absolute_path(const std::string& path) {
    if (path.empty()) {
        return path;
    }
    char resolved_path[PATH_MAX];
    if (realpath(path.c_str(), resolved_path) != nullptr) {
        return std::string(resolved_path);
    }
    return path;
}
