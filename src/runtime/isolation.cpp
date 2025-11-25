#include "runtime/isolation.h"

#include <cerrno>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <vector>

#include "runtime/filesystem.h"
#include "runtime/options.h"

constexpr const char* CGROUP_BASE_PATH = "/sys/fs/cgroup/";

static void write_cgroup_file(const std::string& path, const std::string& value) {
    std::ofstream ofs(path);
    if (!ofs) {
        throw std::runtime_error("Failed to open cgroup file: " + path);
    }
    ofs << value;
}

unsigned long cpu_shares_to_weight(long long shares) {
    if (shares <= 0) {
        return 100;
    }
    if (shares < 2) {
        return 1;
    }
    if (shares > 262144) {
        shares = 262144;
    }
    return static_cast<unsigned long>(1 + ((shares - 2) * 9999) / 262142);
}

void setup_cgroups(pid_t pid,
                   const std::string& id,
                   const LinuxConfig& linux_config,
                   std::string& out_relative_path) {
    log_debug("Setting up cgroups for container " + id);

    std::string relative_path = linux_config.cgroups_path;
    if (!relative_path.empty() && relative_path.front() == '/') {
        relative_path.erase(0, 1);
    }
    while (!relative_path.empty() && relative_path.back() == '/') {
        relative_path.pop_back();
    }
    if (relative_path.empty()) {
        relative_path = "my_runtime/" + id;
    }
    out_relative_path = relative_path;

    const std::string controllers_file = std::string(CGROUP_BASE_PATH) + "cgroup.controllers";
    bool is_cgroup_v2 = (access(controllers_file.c_str(), F_OK) == 0);

    if (is_cgroup_v2) {
        std::set<std::string> available_controllers;
        std::ifstream ctrl_stream(controllers_file);
        if (ctrl_stream) {
            std::string ctrl;
            while (ctrl_stream >> ctrl) {
                available_controllers.insert(ctrl);
            }
        }

        std::vector<std::string> required_controllers;
        if (linux_config.resources.memory_limit > 0) {
            if (!available_controllers.count("memory")) {
                throw std::runtime_error("memory controller not available in cgroup v2");
            }
            required_controllers.emplace_back("memory");
        }
        if (linux_config.resources.cpu_shares > 0) {
            if (!available_controllers.count("cpu")) {
                throw std::runtime_error("cpu controller not available in cgroup v2");
            }
            required_controllers.emplace_back("cpu");
        }

        for (const auto& controller : required_controllers) {
            std::ofstream subtree(std::string(CGROUP_BASE_PATH) + "cgroup.subtree_control");
            if (subtree) {
                subtree << "+" << controller << std::endl;
            }
        }

        std::string unified_path = std::string(CGROUP_BASE_PATH) + relative_path;
        if (!ensure_directory(unified_path, 0755)) {
            throw std::system_error(errno, std::system_category(), "Failed to create unified cgroup dir");
        }

        if (linux_config.resources.memory_limit > 0) {
            write_cgroup_file(unified_path + "/memory.max", std::to_string(linux_config.resources.memory_limit));
        }
        if (linux_config.resources.cpu_shares > 0) {
            unsigned long weight = cpu_shares_to_weight(linux_config.resources.cpu_shares);
            write_cgroup_file(unified_path + "/cpu.weight", std::to_string(weight));
        }

        write_cgroup_file(unified_path + "/cgroup.procs", std::to_string(pid));
        return;
    }

    if (linux_config.resources.memory_limit > 0) {
        std::string mem_cgroup_path = std::string(CGROUP_BASE_PATH) + "memory/" + relative_path;
        if (!ensure_directory(mem_cgroup_path, 0755)) {
            throw std::system_error(errno, std::system_category(), "Failed to create memory cgroup dir");
        }
        write_cgroup_file(mem_cgroup_path + "/memory.limit_in_bytes", std::to_string(linux_config.resources.memory_limit));
        write_cgroup_file(mem_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }

    if (linux_config.resources.cpu_shares > 0) {
        std::string cpu_cgroup_path = std::string(CGROUP_BASE_PATH) + "cpu/" + relative_path;
        if (!ensure_directory(cpu_cgroup_path, 0755)) {
            throw std::system_error(errno, std::system_category(), "Failed to create cpu cgroup dir");
        }
        write_cgroup_file(cpu_cgroup_path + "/cpu.shares", std::to_string(linux_config.resources.cpu_shares));
        write_cgroup_file(cpu_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }
}

void cleanup_cgroups(const std::string& id, const std::string& relative_path_hint) {
    log_debug("Cleaning up cgroups for container " + id);
    std::string relative_path = relative_path_hint;
    if (!relative_path.empty() && relative_path.front() == '/') {
        relative_path.erase(0, 1);
    }
    while (!relative_path.empty() && relative_path.back() == '/') {
        relative_path.pop_back();
    }
    if (relative_path.empty()) {
        relative_path = "my_runtime/" + id;
    }

    const std::string controllers_file = std::string(CGROUP_BASE_PATH) + "cgroup.controllers";
    bool is_cgroup_v2 = (access(controllers_file.c_str(), F_OK) == 0);

    if (is_cgroup_v2) {
        std::string unified_path = std::string(CGROUP_BASE_PATH) + relative_path;
        if (rmdir(unified_path.c_str()) != 0 && errno != ENOENT) {
            perror(("Failed to remove cgroup dir: " + unified_path).c_str());
        }
        return;
    }

    std::string mem_cgroup_path = std::string(CGROUP_BASE_PATH) + "memory/" + relative_path;
    if (rmdir(mem_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove memory cgroup dir: " + mem_cgroup_path).c_str());
    }
    std::string cpu_cgroup_path = std::string(CGROUP_BASE_PATH) + "cpu/" + relative_path;
    if (rmdir(cpu_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove cpu cgroup dir: " + cpu_cgroup_path).c_str());
    }
}

static std::string format_id_mappings(const std::vector<LinuxIDMapping>& mappings) {
    std::ostringstream oss;
    for (const auto& mapping : mappings) {
        oss << mapping.container_id << " " << mapping.host_id << " " << mapping.size << "\n";
    }
    return oss.str();
}

static bool write_mapping_file(const std::string& path, const std::vector<LinuxIDMapping>& mappings) {
    if (mappings.empty()) {
        return true;
    }
    std::ofstream ofs(path);
    if (!ofs) {
        perror(("Failed to open " + path).c_str());
        return false;
    }
    ofs << format_id_mappings(mappings);
    if (!ofs.good()) {
        perror(("Failed to write " + path).c_str());
        return false;
    }
    return true;
}

bool configure_user_namespace(pid_t pid,
                              bool creates_new_userns,
                              const std::vector<LinuxIDMapping>& uid_mappings,
                              const std::vector<LinuxIDMapping>& gid_mappings) {
    if (!creates_new_userns) {
        return true;
    }

    const std::string proc_prefix = "/proc/" + std::to_string(pid);

    if (!gid_mappings.empty()) {
        std::ofstream setgroups_file(proc_prefix + "/setgroups");
        if (setgroups_file) {
            setgroups_file << "deny\n";
            if (!setgroups_file.good()) {
                perror(("Failed to write " + proc_prefix + "/setgroups").c_str());
                return false;
            }
        } else if (errno != ENOENT) {
            perror(("Failed to open " + proc_prefix + "/setgroups").c_str());
            return false;
        }
    }

    if (!write_mapping_file(proc_prefix + "/uid_map", uid_mappings)) {
        return false;
    }
    if (!write_mapping_file(proc_prefix + "/gid_map", gid_mappings)) {
        return false;
    }
    return true;
}
