#include "runtime/config.h"

#include <cstdlib>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <cctype>

#include "json.hpp"

using json = nlohmann::json;

namespace {

std::string normalize_action(std::string value) {
    for (char& ch : value) {
        if (ch == '_') {
            ch = '-';
        } else {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
    }
    return value;
}

bool is_valid_action(const std::string& value, bool allow_allow) {
    if (value == "errno" || value == "kill" || value == "log" || value == "user-notif") {
        return true;
    }
    if (allow_allow && value == "allow") {
        return true;
    }
    return false;
}

bool has_oci_seccomp_keys(const json& j) {
    return j.contains("syscalls") || j.contains("architectures") || j.contains("flags")
           || j.contains("listenerPath") || j.contains("errnoRet");
}

bool has_custom_seccomp_keys(const json& j) {
    return j.contains("policy") || j.contains("allow") || j.contains("deny") || j.contains("rules")
           || j.contains("denyAction") || j.contains("notifySock") || j.contains("errno")
           || j.contains("tsync");
}

int parse_sysno_value(const json& item, const std::string& field_name) {
    if (item.is_number_integer()) {
        return item.get<int>();
    }
    if (item.is_string()) {
        const std::string text = item.get<std::string>();
        std::size_t idx = 0;
        try {
            int value = std::stoi(text, &idx);
            if (idx != text.size()) {
                throw std::runtime_error("invalid syscall value in " + field_name + ": " + text);
            }
            return value;
        } catch (const std::exception&) {
            throw std::runtime_error("invalid syscall value in " + field_name + ": " + text);
        }
    }
    throw std::runtime_error("invalid syscall entry in " + field_name);
}

std::vector<int> parse_sysno_list(const json& value, const std::string& field_name) {
    std::vector<int> out;
    if (value.is_array()) {
        for (const auto& item : value) {
            out.push_back(parse_sysno_value(item, field_name));
        }
        return out;
    }
    if (value.is_string()) {
        std::string list = value.get<std::string>();
        std::stringstream ss(list);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (item.empty()) {
                continue;
            }
            json tmp = item;
            out.push_back(parse_sysno_value(tmp, field_name));
        }
        return out;
    }
    throw std::runtime_error("invalid syscall list for " + field_name);
}

} // namespace

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

void from_json(const json& j, SeccompConfig& seccomp) {
    seccomp.enabled = true;
    if (j.contains("enabled")) {
        j.at("enabled").get_to(seccomp.enabled);
    }
    if (j.contains("binary")) {
        j.at("binary").get_to(seccomp.binary);
    }
    if (j.contains("ociConfigPath")) {
        j.at("ociConfigPath").get_to(seccomp.oci_config_path);
    }

    bool oci_hint = false;
    if (j.contains("oci")) {
        j.at("oci").get_to(oci_hint);
    }

    const bool has_oci_keys = has_oci_seccomp_keys(j);
    const bool has_custom_keys = has_custom_seccomp_keys(j);

    if ((oci_hint || has_oci_keys) && has_custom_keys) {
        throw std::runtime_error("seccomp config mixes OCI and custom fields");
    }

    if (!seccomp.enabled) {
        return;
    }

    if (oci_hint || has_oci_keys) {
        seccomp.oci_mode = true;
        seccomp.oci_json = j.dump();
        return;
    }

    if (j.contains("policy")) {
        j.at("policy").get_to(seccomp.policy);
    }
    if (j.contains("allow")) {
        seccomp.allow = parse_sysno_list(j.at("allow"), "seccomp.allow");
    }
    if (j.contains("deny")) {
        seccomp.deny = parse_sysno_list(j.at("deny"), "seccomp.deny");
    }
    if (j.contains("rules")) {
        j.at("rules").get_to(seccomp.rules);
    }
    if (j.contains("defaultAction")) {
        j.at("defaultAction").get_to(seccomp.default_action);
        seccomp.default_action = normalize_action(seccomp.default_action);
        if (!is_valid_action(seccomp.default_action, true)) {
            throw std::runtime_error("seccomp.defaultAction is invalid: " + seccomp.default_action);
        }
    }
    if (j.contains("denyAction")) {
        j.at("denyAction").get_to(seccomp.deny_action);
        seccomp.deny_action = normalize_action(seccomp.deny_action);
        if (!is_valid_action(seccomp.deny_action, false)) {
            throw std::runtime_error("seccomp.denyAction is invalid: " + seccomp.deny_action);
        }
    }
    if (j.contains("errno")) {
        j.at("errno").get_to(seccomp.errno_ret);
        if (seccomp.errno_ret <= 0) {
            throw std::runtime_error("seccomp.errno must be > 0");
        }
    }
    if (j.contains("tsync")) {
        j.at("tsync").get_to(seccomp.tsync);
    }
    if (j.contains("notifySock")) {
        j.at("notifySock").get_to(seccomp.notify_sock);
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
    if (j.contains("seccomp")) {
        j.at("seccomp").get_to(l.seccomp);
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
