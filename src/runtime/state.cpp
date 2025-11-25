#include "runtime/state.h"

#include <cerrno>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>

#include "runtime/filesystem.h"
#include "runtime/options.h"

json ContainerState::to_json_object() const {
    std::string reported_version = version.empty() ? (oci_version.empty() ? RUNTIME_VERSION : oci_version) : version;
    std::string reported_oci = oci_version.empty() ? reported_version : oci_version;
    json j = {
            {"version", reported_version},
            {"ociVersion", reported_oci},
            {"id", id},
            {"status", status},
            {"pid", pid >= 0 ? pid : 0},
            {"bundle", bundle_path.empty() ? "." : bundle_path}
    };
    if (!annotations.empty()) {
        j["annotations"] = annotations;
    }
    return j;
}

std::string ContainerState::to_json() const {
    return to_json_object().dump(4);
}

ContainerState ContainerState::from_json(const std::string& json_str) {
    ContainerState state;
    json j = json::parse(json_str);
    if (j.contains("version")) {
        j.at("version").get_to(state.version);
    }
    if (j.contains("ociVersion")) {
        j.at("ociVersion").get_to(state.oci_version);
        if (state.version.empty()) {
            state.version = state.oci_version;
        }
    }
    j.at("id").get_to(state.id);
    j.at("pid").get_to(state.pid);
    j.at("status").get_to(state.status);
    if (j.contains("bundle")) {
        j.at("bundle").get_to(state.bundle_path);
    } else if (j.contains("bundle_path")) {
        j.at("bundle_path").get_to(state.bundle_path);
    }
    if (j.contains("annotations")) {
        j.at("annotations").get_to(state.annotations);
    }
    return state;
}

bool save_state(const ContainerState& state) {
    std::string container_path = state_base_path() + state.id;
    std::string state_file_path = container_path + "/state.json";
    if (mkdir(container_path.c_str(), 0755) != 0 && errno != EEXIST) {
        perror("Failed to create state directory");
        return false;
    }
    std::ofstream ofs(state_file_path);
    if (!ofs) {
        std::cerr << "Failed to open state file: " << state_file_path << std::endl;
        return false;
    }
    ofs << state.to_json();
    return true;
}

ContainerState load_state(const std::string& container_id) {
    std::string state_file_path = state_base_path() + container_id + "/state.json";
    std::ifstream ifs(state_file_path);
    if (!ifs) {
        throw std::runtime_error("Failed to load state file: " + state_file_path);
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return ContainerState::from_json(buffer.str());
}

std::string get_fifo_path(const std::string& container_id) {
    return state_base_path() + container_id + "/sync_fifo";
}

std::string events_file_path(const std::string& id) {
    return state_base_path() + id + "/events.log";
}

std::string iso8601_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto seconds = system_clock::to_time_t(now);
    std::tm tm {};
    gmtime_r(&seconds, &tm);
    auto millis = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%FT%T") << '.' << std::setfill('0') << std::setw(3) << millis.count() << 'Z';
    return oss.str();
}

void record_event(const std::string& id, const std::string& type, const json& data) {
    std::string path = events_file_path(id);
    if (!ensure_parent_directory(path)) {
        std::cerr << "Failed to prepare events log for container '" << id << "'" << std::endl;
        return;
    }
    std::ofstream ofs(path, std::ios::app);
    if (!ofs) {
        std::cerr << "Failed to open events log for container '" << id << "'" << std::endl;
        return;
    }
    json entry = {
            {"timestamp", iso8601_now()},
            {"type", type},
            {"id", id}
    };
    if (!data.is_null()) {
        entry["data"] = data;
    }
    ofs << entry.dump() << std::endl;
}

void record_state_event(const ContainerState& state) {
    record_event(state.id, "state", state.to_json_object());
}

bool write_pid_file(const std::string& pid_file, pid_t pid) {
    if (pid_file.empty()) {
        return true;
    }
    std::ofstream ofs(pid_file);
    if (!ofs) {
        std::cerr << "Failed to open pid file: " << pid_file << std::endl;
        return false;
    }
    ofs << pid;
    return true;
}
