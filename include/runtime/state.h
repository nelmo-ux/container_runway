#pragma once

#include <map>
#include <string>
#include <sys/types.h>

#include "json.hpp"

using json = nlohmann::json;

struct ContainerState {
    std::string version;
    std::string oci_version;
    std::string id;
    pid_t pid = -1;
    std::string status;
    std::string bundle_path;
    std::map<std::string, std::string> annotations;

    json to_json_object() const;
    std::string to_json() const;
    static ContainerState from_json(const std::string& json_str);
};

bool save_state(const ContainerState& state);
ContainerState load_state(const std::string& container_id);

std::string get_fifo_path(const std::string& container_id);
std::string events_file_path(const std::string& id);
std::string iso8601_now();
void record_event(const std::string& id, const std::string& type, const json& data = json::object());
void record_state_event(const ContainerState& state);
bool write_pid_file(const std::string& pid_file, pid_t pid);
