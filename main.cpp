#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <system_error>
#include <getopt.h>
#include <memory>
#include <cerrno>
#include <algorithm>
#include <limits.h>
#include <cstdint>
#include <set>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <thread>
#include <queue>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "json.hpp"

// A convenient alias for nlohmann::json
using json = nlohmann::json;

extern char** environ;

constexpr int STACK_SIZE = 1024 * 1024; // 1MB

// Base path for cgroups
const std::string CGROUP_BASE_PATH = "/sys/fs/cgroup/";

struct GlobalOptions {
    bool debug = false;
    bool systemd_cgroup = false;
    std::string log_path;
    std::string log_format = "text";
    std::string root_path;
};

static GlobalOptions g_global_options;
static std::unique_ptr<std::ofstream> g_log_stream;
static const std::string RUNTIME_VERSION = "0.1.0";

enum GlobalOptionValue {
    OPT_DEBUG = 1000,
    OPT_LOG,
    OPT_LOG_FORMAT,
    OPT_ROOT,
    OPT_VERSION,
    OPT_HELP,
    OPT_SYSTEMD_CGROUP
};

std::string ensure_trailing_slash(const std::string& path) {
    if (path.empty() || path.back() == '/') {
        return path;
    }
    return path + "/";
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

bool configure_log_destination(const std::string& path) {
    std::unique_ptr<std::ofstream> stream(new std::ofstream(path, std::ios::app));
    if (!stream || !(*stream)) {
        std::cerr << "Failed to open log file: " << path << std::endl;
        return false;
    }
    g_log_stream = std::move(stream);
    std::cerr.rdbuf(g_log_stream->rdbuf());
    return true;
}

void log_debug(const std::string& message) {
    if (g_global_options.debug) {
        std::cerr << "[debug] " << message << std::endl;
    }
}

// --- C++ structs corresponding to the config.json structure ---

struct ProcessConfig {
    bool terminal;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd = "/";
};

struct RootConfig {
    std::string path;
    bool readonly;
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

// Cgroup向けのコンフィグ設定
struct LinuxResourcesConfig {
    long long memory_limit = 0; // memory.limit_in_bytes
    long long cpu_shares = 0;   // cpu.shares
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

// config Jsonのパース用構造
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

// --- JSONファイルの読み込み ---

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

// Jsonのパース系
// Note: Cgroups系の処理がメインPIDに対してのみかかっている可能性
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

// RW とパース用関数
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

// FIFO用のヘルパー関数 以下 Claude生成
std::string get_fifo_path(const std::string& container_id) {
    return state_base_path() + container_id + "/sync_fifo";
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

// Struct to hold arguments for the container
struct ContainerArgs {
    std::vector<std::string> process_args;
    std::vector<std::string> process_env;
    std::string process_cwd = "/";
    std::string sync_fifo_path;
    std::string rootfs_path;
    std::string hostname;
    bool rootfs_readonly;
    bool enable_pivot_root = true;
    std::vector<MountConfig> mounts;
    std::vector<std::string> masked_paths;
    std::vector<std::string> readonly_paths;
    std::string rootfs_propagation;
    std::vector<std::pair<int, int>> join_namespaces;
    bool terminal = false;
    int console_slave_fd = -1;
};

struct CreateOptions {
    std::string id;
    std::string bundle = ".";
    std::string pid_file;
    std::string console_socket;
    bool no_pivot = false;
    int preserve_fds = 0;
    std::string notify_socket;
};

struct ExecOptions {
    std::string id;
    std::string pid_file;
    std::string process_path;
    bool detach = false;
    bool tty = false;
    int preserve_fds = 0;
    std::vector<std::string> args;
};

struct EventsOptions {
    std::string id;
    bool follow = false;
    bool stats = false;
    int interval_ms = 1000;
};

// Struct to represent the container's state
struct ContainerState {
    std::string version;
    std::string oci_version;
    std::string id;
    pid_t pid = -1;
    std::string status; // creating, created, running, stopped
    std::string bundle_path;
    std::map<std::string, std::string> annotations;

    json to_json_object() const {
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

    std::string to_json() const {
        return to_json_object().dump(4);
    }

    static ContainerState from_json(const std::string& json_str) {
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
};

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
//ここまで


//Cgroup系の処理

bool write_pid_file(const std::string& pid_file, pid_t pid) {
    std::ofstream ofs(pid_file);
    if (!ofs) {
        std::cerr << "Failed to open pid file: " << pid_file << std::endl;
        return false;
    }
    ofs << pid << std::endl;
    return true;
}

// Helper to write to a cgroup file
void write_cgroup_file(const std::string& path, const std::string& value) {
    std::ofstream ofs(path);
    if (!ofs) {
        throw std::runtime_error("Failed to open cgroup file: " + path);
    }
    ofs << value;
}

bool ensure_directory(const std::string& path, mode_t mode = 0755);
unsigned long cpu_shares_to_weight(long long shares);
bool ensure_parent_directory(const std::string& path);
std::string iso8601_now();
std::string events_file_path(const std::string& id);
void record_event(const std::string& id, const std::string& type, const json& data = json::object());
bool wait_for_process(pid_t pid, int timeout_sec, int& status);
bool run_hook_sequence(const std::vector<HookConfig>& hooks,
                       ContainerState& state,
                       const std::string& hook_type,
                       bool enforce_once = true);

//seccomp系アタッチ
//void attach_bpf(pid_t pid, int& syscalls[], bool isActive){
//    //Todo: BPF処理を外部実装
//}

// 制限のアタッチ
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

    const std::string controllers_file = CGROUP_BASE_PATH + "cgroup.controllers";
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
            std::ofstream subtree(CGROUP_BASE_PATH + "cgroup.subtree_control");
            if (subtree) {
                subtree << "+" << controller << std::endl;
            }
        }

        std::string unified_path = CGROUP_BASE_PATH + relative_path;
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

    // Memory Cgroup
    if (linux_config.resources.memory_limit > 0) {
        std::string mem_cgroup_path = CGROUP_BASE_PATH + "memory/" + relative_path;
        if (!ensure_directory(mem_cgroup_path, 0755)) {
            throw std::system_error(errno, std::system_category(), "Failed to create memory cgroup dir");
        }
        write_cgroup_file(mem_cgroup_path + "/memory.limit_in_bytes", std::to_string(linux_config.resources.memory_limit));
        write_cgroup_file(mem_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }

    // CPU Cgroup
    if (linux_config.resources.cpu_shares > 0) {
        std::string cpu_cgroup_path = CGROUP_BASE_PATH + "cpu/" + relative_path;
        if (!ensure_directory(cpu_cgroup_path, 0755)) {
            throw std::system_error(errno, std::system_category(), "Failed to create cpu cgroup dir");
        }
        write_cgroup_file(cpu_cgroup_path + "/cpu.shares", std::to_string(linux_config.resources.cpu_shares));
        write_cgroup_file(cpu_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }
}

// Cleans up cgroups for the container
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

    const std::string controllers_file = CGROUP_BASE_PATH + "cgroup.controllers";
    bool is_cgroup_v2 = (access(controllers_file.c_str(), F_OK) == 0);

    if (is_cgroup_v2) {
        std::string unified_path = CGROUP_BASE_PATH + relative_path;
        if (rmdir(unified_path.c_str()) != 0 && errno != ENOENT) {
            perror(("Failed to remove cgroup dir: " + unified_path).c_str());
        }
        return;
    }

    std::string mem_cgroup_path = CGROUP_BASE_PATH + "memory/" + relative_path;
    if (rmdir(mem_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove memory cgroup dir: " + mem_cgroup_path).c_str());
    }
    std::string cpu_cgroup_path = CGROUP_BASE_PATH + "cpu/" + relative_path;
    if (rmdir(cpu_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove cpu cgroup dir: " + cpu_cgroup_path).c_str());
    }
}

struct ConsolePair {
    int master_fd = -1;
    int slave_fd = -1;
    std::string slave_name;
};

void close_console_pair(ConsolePair& pair) {
    if (pair.master_fd >= 0) {
        close(pair.master_fd);
        pair.master_fd = -1;
    }
    if (pair.slave_fd >= 0) {
        close(pair.slave_fd);
        pair.slave_fd = -1;
    }
}

bool allocate_console_pair(ConsolePair& pair, std::string& error_message) {
    ConsolePair tmp;
    tmp.master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tmp.master_fd == -1) {
        error_message = std::string("posix_openpt failed: ") + std::strerror(errno);
        return false;
    }
    if (grantpt(tmp.master_fd) != 0) {
        error_message = std::string("grantpt failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    if (unlockpt(tmp.master_fd) != 0) {
        error_message = std::string("unlockpt failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    char slave_name_buf[PATH_MAX];
    if (ptsname_r(tmp.master_fd, slave_name_buf, sizeof(slave_name_buf)) != 0) {
        error_message = std::string("ptsname_r failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    tmp.slave_name = slave_name_buf;
    tmp.slave_fd = open(slave_name_buf, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tmp.slave_fd == -1) {
        error_message = std::string("open slave pty failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    pair = tmp;
    return true;
}

bool send_console_fd(const ConsolePair& pair, const std::string& socket_path, std::string& error_message) {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        error_message = std::string("socket creation failed: ") + std::strerror(errno);
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        error_message = "console socket path too long";
        close(sock);
        return false;
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error_message = std::string("connect to console socket failed: ") + std::strerror(errno);
        close(sock);
        return false;
    }

    std::string payload = pair.slave_name.empty() ? "console" : pair.slave_name;
    struct iovec iov{};
    iov.iov_base = const_cast<char*>(payload.c_str());
    iov.iov_len = payload.size();

    char control[CMSG_SPACE(sizeof(int))];
    std::memset(control, 0, sizeof(control));

    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &pair.master_fd, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    ssize_t sent = sendmsg(sock, &msg, 0);
    int saved_errno = errno;
    close(sock);
    if (sent == -1) {
        error_message = std::string("sendmsg failed: ") + std::strerror(saved_errno);
        return false;
    }
    return true;
}

std::string iso8601_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto seconds = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&seconds, &tm);
    auto millis = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%FT%T") << '.' << std::setfill('0') << std::setw(3) << millis.count() << 'Z';
    return oss.str();
}

std::string events_file_path(const std::string& id) {
    return state_base_path() + id + "/events.log";
}

bool wait_for_process(pid_t pid, int timeout_sec, int& status) {
    if (timeout_sec <= 0) {
        return waitpid(pid, &status, 0) == pid;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (true) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            return true;
        }
        if (result == -1) {
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            errno = ETIMEDOUT;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

bool write_all(int fd, const std::string& data) {
    size_t written = 0;
    while (written < data.size()) {
        ssize_t n = write(fd, data.data() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        written += static_cast<size_t>(n);
    }
    return true;
}

bool execute_single_hook(const HookConfig& hook,
                         const ContainerState& state,
                         const std::string& hook_type) {
    if (hook.path.empty()) {
        std::cerr << "Hook path is empty for " << hook_type << std::endl;
        return false;
    }
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        perror("pipe for hook stdin failed");
        return false;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork for hook failed");
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return false;
    }

    if (pid == 0) {
        close(pipe_fds[1]);
        if (dup2(pipe_fds[0], STDIN_FILENO) == -1) {
            perror("dup2 failed for hook stdin");
            _exit(127);
        }
        close(pipe_fds[0]);

        std::vector<std::string> args = hook.args.empty() ? std::vector<std::string>{hook.path} : hook.args;
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        std::vector<std::string> env_strings;
        for (char** env = environ; env && *env; ++env) {
            env_strings.emplace_back(*env);
        }
        env_strings.emplace_back("OCI_HOOK_TYPE=" + hook_type);
        env_strings.emplace_back("OCI_CONTAINER_ID=" + state.id);
        env_strings.emplace_back("OCI_CONTAINER_BUNDLE=" + (state.bundle_path.empty() ? "." : state.bundle_path));
        env_strings.emplace_back("OCI_CONTAINER_PID=" + std::to_string(state.pid));
        env_strings.emplace_back("OCI_CONTAINER_STATUS=" + state.status);
        for (const auto& env_entry : hook.env) {
            env_strings.emplace_back(env_entry);
        }

        std::vector<char*> envp;
        envp.reserve(env_strings.size() + 1);
        for (auto& env_entry : env_strings) {
            envp.push_back(const_cast<char*>(env_entry.c_str()));
        }
        envp.push_back(nullptr);

        execve(hook.path.c_str(), argv.data(), envp.data());
        perror(("Failed to exec hook: " + hook.path).c_str());
        _exit(127);
    }

    close(pipe_fds[0]);
    std::string payload = state.to_json();
    bool write_ok = write_all(pipe_fds[1], payload);
    close(pipe_fds[1]);
    if (!write_ok) {
        std::cerr << "Failed to write container state to hook stdin: " << hook.path << std::endl;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        return false;
    }

    int status = 0;
    if (!wait_for_process(pid, hook.timeout, status)) {
        std::cerr << "Hook '" << hook.path << "' timed out or failed for " << hook_type << std::endl;
        return false;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return true;
    }
    if (WIFEXITED(status)) {
        std::cerr << "Hook '" << hook.path << "' exited with status "
                  << WEXITSTATUS(status) << " for " << hook_type << std::endl;
    } else if (WIFSIGNALED(status)) {
        std::cerr << "Hook '" << hook.path << "' terminated by signal "
                  << WTERMSIG(status) << " for " << hook_type << std::endl;
    }
    return false;
}

bool run_hook_sequence(const std::vector<HookConfig>& hooks,
                       ContainerState& state,
                       const std::string& hook_type,
                       bool enforce_once) {
    if (hooks.empty()) {
        return true;
    }
    std::string annotation_key = "runway.hooks." + hook_type;
    if (enforce_once) {
        auto it = state.annotations.find(annotation_key);
        if (it != state.annotations.end()) {
            return true;
        }
    }
    for (const auto& hook : hooks) {
        if (!execute_single_hook(hook, state, hook_type)) {
            return false;
        }
    }
    state.annotations[annotation_key] = iso8601_now();
    return true;
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

std::string format_id_mappings(const std::vector<LinuxIDMapping>& mappings) {
    std::ostringstream oss;
    for (const auto& mapping : mappings) {
        oss << mapping.container_id << " " << mapping.host_id << " " << mapping.size << "\n";
    }
    return oss.str();
}

bool write_mapping_file(const std::string& path, const std::vector<LinuxIDMapping>& mappings) {
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

struct ParsedMountOptions {
    unsigned long flags = 0;
    unsigned long propagation = 0;
    bool has_propagation = false;
    bool bind_readonly = false;
    std::string data;
};

std::string join_strings(const std::vector<std::string>& parts, const char* delimiter = ",") {
    if (parts.empty()) {
        return "";
    }
    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            oss << delimiter;
        }
        oss << parts[i];
    }
    return oss.str();
}

ParsedMountOptions parse_mount_options(const std::vector<std::string>& options) {
    ParsedMountOptions parsed;
    std::vector<std::string> data_options;
    for (const auto& opt : options) {
        if (opt == "ro") {
            parsed.flags |= MS_RDONLY;
        } else if (opt == "rw") {
            parsed.flags &= ~MS_RDONLY;
        } else if (opt == "nosuid") {
            parsed.flags |= MS_NOSUID;
        } else if (opt == "nodev") {
            parsed.flags |= MS_NODEV;
        } else if (opt == "noexec") {
            parsed.flags |= MS_NOEXEC;
        } else if (opt == "relatime") {
            parsed.flags |= MS_RELATIME;
        } else if (opt == "norelatime") {
            parsed.flags &= ~MS_RELATIME;
        } else if (opt == "strictatime") {
            parsed.flags |= MS_STRICTATIME;
        } else if (opt == "nostrictatime") {
            parsed.flags &= ~MS_STRICTATIME;
        } else if (opt == "sync") {
            parsed.flags |= MS_SYNCHRONOUS;
        } else if (opt == "dirsync") {
            parsed.flags |= MS_DIRSYNC;
        } else if (opt == "remount") {
            parsed.flags |= MS_REMOUNT;
        } else if (opt == "bind") {
            parsed.flags |= MS_BIND;
        } else if (opt == "rbind") {
            parsed.flags |= (MS_BIND | MS_REC);
        } else if (opt == "recursive") {
            parsed.flags |= MS_REC;
        } else if (opt == "private") {
            parsed.propagation = MS_PRIVATE;
            parsed.has_propagation = true;
        } else if (opt == "rprivate") {
            parsed.propagation = MS_PRIVATE | MS_REC;
            parsed.has_propagation = true;
        } else if (opt == "shared") {
            parsed.propagation = MS_SHARED;
            parsed.has_propagation = true;
        } else if (opt == "rshared") {
            parsed.propagation = MS_SHARED | MS_REC;
            parsed.has_propagation = true;
        } else if (opt == "slave") {
            parsed.propagation = MS_SLAVE;
            parsed.has_propagation = true;
        } else if (opt == "rslave") {
            parsed.propagation = MS_SLAVE | MS_REC;
            parsed.has_propagation = true;
        } else if (opt == "unbindable") {
            parsed.propagation = MS_UNBINDABLE;
            parsed.has_propagation = true;
        } else if (opt == "runbindable") {
            parsed.propagation = MS_UNBINDABLE | MS_REC;
            parsed.has_propagation = true;
        } else if (opt.find('=') != std::string::npos) {
            data_options.push_back(opt);
        } else {
            data_options.push_back(opt);
        }
    }
    parsed.data = join_strings(data_options);
    if ((parsed.flags & MS_BIND) && (parsed.flags & MS_RDONLY)) {
        parsed.bind_readonly = true;
    }
    return parsed;
}

bool ensure_directory(const std::string& path, mode_t mode) {
    if (path.empty()) {
        return false;
    }
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    std::string parent;
    auto pos = path.find_last_of('/');
    if (pos != std::string::npos && pos != 0) {
        parent = path.substr(0, pos);
    } else if (pos == 0) {
        parent = "/";
    }
    if (!parent.empty() && parent != path) {
        if (!ensure_directory(parent, mode)) {
            return false;
        }
    }
    if (mkdir(path.c_str(), mode) == 0 || errno == EEXIST) {
        return true;
    }
    return false;
}

bool ensure_parent_directory(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos || pos == 0) {
        return true;
    }
    return ensure_directory(path.substr(0, pos));
}

bool ensure_file(const std::string& path, mode_t mode = 0644) {
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        return S_ISREG(st.st_mode);
    }
    if (!ensure_parent_directory(path)) {
        return false;
    }
    int fd = open(path.c_str(), O_CREAT | O_CLOEXEC | O_WRONLY, mode);
    if (fd == -1) {
        return false;
    }
    close(fd);
    return true;
}

bool ensure_runtime_root_directory() {
    if (g_global_options.root_path.empty()) {
        g_global_options.root_path = default_state_root();
    }
    if (g_global_options.root_path.size() > 1 && g_global_options.root_path.back() == '/') {
        g_global_options.root_path.pop_back();
    }
    if (ensure_directory(g_global_options.root_path, 0755)) {
        return true;
    }
    int primary_error = errno;
    if (geteuid() != 0) {
        std::string fallback = fallback_state_root();
        if (fallback.size() > 1 && fallback.back() == '/') {
            fallback.pop_back();
        }
        if (fallback != g_global_options.root_path) {
            log_debug("Unable to use preferred state root '" + g_global_options.root_path +
                      "': " + std::strerror(primary_error));
            if (ensure_directory(fallback, 0755)) {
                log_debug("Falling back to runtime state root '" + fallback + "'");
                g_global_options.root_path = fallback;
                return true;
            }
            std::cerr << "Failed to create runtime root directory '" << fallback
                      << "': " << std::strerror(errno) << std::endl;
            return false;
        }
    }
    std::cerr << "Failed to create runtime root directory '" << g_global_options.root_path
              << "': " << std::strerror(primary_error) << std::endl;
    return false;
}

std::string container_absolute_path(const std::string& rootfs, const std::string& path) {
    if (path.empty() || path == ".") {
        return rootfs;
    }
    if (path.front() == '/') {
        return rootfs + path;
    }
    return rootfs + "/" + path;
}

unsigned long propagation_flag_from_string(const std::string& propagation) {
    if (propagation == "private") {
        return MS_PRIVATE;
    }
    if (propagation == "rprivate") {
        return MS_PRIVATE | MS_REC;
    }
    if (propagation == "shared") {
        return MS_SHARED;
    }
    if (propagation == "rshared") {
        return MS_SHARED | MS_REC;
    }
    if (propagation == "slave") {
        return MS_SLAVE;
    }
    if (propagation == "rslave") {
        return MS_SLAVE | MS_REC;
    }
    if (propagation == "unbindable") {
        return MS_UNBINDABLE;
    }
    if (propagation == "runbindable") {
        return MS_UNBINDABLE | MS_REC;
    }
    return 0;
}

bool apply_mount_propagation(const std::string& path, const std::string& propagation) {
    if (propagation.empty()) {
        return true;
    }
    unsigned long flag = propagation_flag_from_string(propagation);
    if (flag == 0) {
        std::cerr << "Unknown rootfs propagation mode: " << propagation << std::endl;
        return false;
    }
    if (mount(nullptr, path.c_str(), nullptr, flag, nullptr) != 0) {
        perror(("Failed to set propagation on " + path).c_str());
        return false;
    }
    return true;
}


// Entry point for the child process (container)
int container_main(void* arg) {
    std::unique_ptr<ContainerArgs> args_holder(static_cast<ContainerArgs*>(arg));
    ContainerArgs* args = args_holder.get();

    for (auto& ns_fd : args->join_namespaces) {
        if (setns(ns_fd.first, ns_fd.second) != 0) {
            perror("setns failed");
            return 1;
        }
        close(ns_fd.first);
    }
    args->join_namespaces.clear();

    // 1. Wait for the start signal from the parent process
    char buf;
    int fifo_fd = open(args->sync_fifo_path.c_str(), O_RDONLY);
    if (fifo_fd == -1) {
        perror("Failed to open FIFO (read)");
        return 1;
    }
    if (read(fifo_fd, &buf, 1) <= 0) {
        close(fifo_fd);
        return 1;
    }
    close(fifo_fd);

    // 2. Set up the environment
    if (sethostname(args->hostname.c_str(), args->hostname.length()) != 0) {
        perror("sethostname failed");
        return 1;
    }

    const std::string rootfs = args->rootfs_path;
    if (mount(rootfs.c_str(), rootfs.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        perror("Failed to bind-mount rootfs");
        return 1;
    }

    if (!args->rootfs_propagation.empty()) {
        if (!apply_mount_propagation(rootfs, args->rootfs_propagation)) {
            return 1;
        }
    }

    if (chdir(rootfs.c_str()) != 0) {
        perror("chdir to rootfs failed");
        return 1;
    }

    for (const auto& mount_cfg : args->mounts) {
        std::string destination = mount_cfg.destination;
        if (destination.empty()) {
            continue;
        }
        if (destination.front() != '/') {
            destination = "/" + destination;
        }
        const std::string mount_target = container_absolute_path(rootfs, destination);
        ParsedMountOptions parsed = parse_mount_options(mount_cfg.options);
        const bool is_bind = (parsed.flags & MS_BIND) || mount_cfg.type == "bind";

        bool source_is_dir = true;
        if (!mount_cfg.source.empty()) {
            struct stat source_stat{};
            if (stat(mount_cfg.source.c_str(), &source_stat) == 0) {
                source_is_dir = S_ISDIR(source_stat.st_mode);
            } else if (is_bind) {
                perror(("Failed to stat mount source: " + mount_cfg.source).c_str());
                return 1;
            }
        }

        if (source_is_dir) {
            if (!ensure_directory(mount_target)) {
                std::cerr << "Failed to ensure mount target directory: " << mount_target << std::endl;
                return 1;
            }
        } else {
            if (!ensure_file(mount_target)) {
                std::cerr << "Failed to ensure mount target file: " << mount_target << std::endl;
                return 1;
            }
        }

        const char* source = mount_cfg.source.empty() ? nullptr : mount_cfg.source.c_str();
        const char* fs_type = mount_cfg.type.empty() ? nullptr : mount_cfg.type.c_str();
        unsigned long first_flags = parsed.flags & ~MS_REMOUNT;
        if (parsed.bind_readonly) {
            first_flags &= ~MS_RDONLY;
        }

        if (mount(source, mount_target.c_str(), fs_type,
                  first_flags,
                  parsed.data.empty() ? nullptr : parsed.data.c_str()) != 0) {
            perror(("Failed to mount " + destination).c_str());
            return 1;
        }

        if (parsed.bind_readonly) {
            unsigned long remount_flags = parsed.flags | MS_REMOUNT;
            if (mount(nullptr, mount_target.c_str(), nullptr, remount_flags, nullptr) != 0) {
                perror(("Failed to remount readonly " + destination).c_str());
                return 1;
            }
        } else if (parsed.flags & MS_REMOUNT) {
            if (mount(source, mount_target.c_str(), fs_type,
                      parsed.flags,
                      parsed.data.empty() ? nullptr : parsed.data.c_str()) != 0) {
                perror(("Failed to remount " + destination).c_str());
                return 1;
            }
        }

        if (parsed.has_propagation) {
            if (mount(nullptr, mount_target.c_str(), nullptr, parsed.propagation, nullptr) != 0) {
                perror(("Failed to set propagation on " + destination).c_str());
                return 1;
            }
        }
    }

    for (const auto& masked : args->masked_paths) {
        if (masked.empty()) {
            continue;
        }
        std::string target = container_absolute_path(rootfs, masked);
        struct stat st{};
        bool is_dir = false;
        if (lstat(target.c_str(), &st) == 0) {
            is_dir = S_ISDIR(st.st_mode);
        } else {
            if (masked.back() == '/') {
                if (!ensure_directory(target)) {
                    std::cerr << "Failed to create masked directory: " << target << std::endl;
                    return 1;
                }
                is_dir = true;
            } else if (ensure_file(target)) {
                is_dir = false;
            } else if (ensure_directory(target)) {
                is_dir = true;
            }
        }

        if (is_dir) {
            if (mount("tmpfs", target.c_str(), "tmpfs",
                      MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                      "size=0") != 0) {
                perror(("Failed to mask directory " + masked).c_str());
                return 1;
            }
        } else {
            if (!ensure_file(target)) {
                std::cerr << "Failed to create masked file: " << target << std::endl;
                return 1;
            }
            if (mount("/dev/null", target.c_str(), nullptr, MS_BIND, nullptr) != 0) {
                perror(("Failed to mask file " + masked).c_str());
                return 1;
            }
        }
    }

    for (const auto& ro_path : args->readonly_paths) {
        if (ro_path.empty()) {
            continue;
        }
        std::string target = container_absolute_path(rootfs, ro_path);
        struct stat st{};
        if (stat(target.c_str(), &st) != 0) {
            // Attempt to create the path if it doesn't exist.
            if (ro_path.back() == '/') {
                if (!ensure_directory(target)) {
                    std::cerr << "Failed to prepare readonly directory: " << target << std::endl;
                    return 1;
                }
            } else if (!ensure_file(target) && !ensure_directory(target)) {
                std::cerr << "Failed to prepare readonly path: " << target << std::endl;
                return 1;
            }
        }
        if (mount(target.c_str(), target.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
            perror(("Failed to bind-mount readonly path " + ro_path).c_str());
            return 1;
        }
        if (mount(nullptr, target.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_REC | MS_RDONLY, nullptr) != 0) {
            perror(("Failed to remount readonly path " + ro_path).c_str());
            return 1;
        }
    }

    bool pivot_succeeded = false;
    if (args->enable_pivot_root) {
        const std::string old_root_dir = ".runway-oldroot";
        if (!ensure_directory(old_root_dir, 0700)) {
            std::cerr << "Failed to prepare old root directory for pivot_root" << std::endl;
        } else if (syscall(SYS_pivot_root, ".", old_root_dir.c_str()) != 0) {
            perror("pivot_root failed");
        } else {
            pivot_succeeded = true;
            if (chdir("/") != 0) {
                perror("chdir to new root failed");
                return 1;
            }
            if (umount2(("/" + old_root_dir).c_str(), MNT_DETACH) != 0) {
                perror("Failed to unmount old root");
            }
            if (rmdir(("/" + old_root_dir).c_str()) != 0) {
                perror("Failed to remove old root directory");
            }
        }
    }

    if (!pivot_succeeded) {
        if (chroot(".") != 0) {
            perror("chroot failed");
            return 1;
        }
        if (chdir("/") != 0) {
            perror("chdir to / failed");
            return 1;
        }
    }

    if (!args->rootfs_propagation.empty()) {
        if (!apply_mount_propagation("/", args->rootfs_propagation)) {
            return 1;
        }
    }

    const std::string target_cwd = args->process_cwd.empty() ? "/" : args->process_cwd;
    if (chdir(target_cwd.c_str()) != 0) {
        perror("Failed to set process cwd");
        return 1;
    }

    if (mount("proc", "/proc", "proc", 0, nullptr) != 0) {
        perror("Failed to mount proc");
    }

    if (args->rootfs_readonly) {
        if (mount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr) != 0) {
            perror("Failed to remount rootfs as readonly");
        }
    }

    if (args->terminal && args->console_slave_fd >= 0) {
        if (setsid() == -1) {
            perror("setsid failed");
            return 1;
        }
        if (ioctl(args->console_slave_fd, TIOCSCTTY, 0) == -1) {
            perror("Failed to set controlling terminal");
            return 1;
        }
        for (int fd = 0; fd < 3; ++fd) {
            if (dup2(args->console_slave_fd, fd) == -1) {
                perror("dup2 failed for console");
                return 1;
            }
        }
        if (args->console_slave_fd > STDERR_FILENO) {
            close(args->console_slave_fd);
        }
        args->console_slave_fd = -1;
    }

    if (!args->process_env.empty()) {
        if (clearenv() != 0) {
            perror("clearenv failed");
            return 1;
        }
        for (const auto& env_entry : args->process_env) {
            std::size_t eq_pos = env_entry.find('=');
            std::string key = env_entry.substr(0, eq_pos);
            std::string value = (eq_pos == std::string::npos) ? "" : env_entry.substr(eq_pos + 1);
            if (key.empty()) {
                continue;
            }
            if (setenv(key.c_str(), value.c_str(), 1) != 0) {
                perror("setenv failed");
                return 1;
            }
        }
    }

    // 3. Execute the specified command
    std::vector<char*> argv;
    argv.reserve(args->process_args.size() + 1);
    for (const auto& arg : args->process_args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);
    if (execvp(argv[0], argv.data())) {
        perror("execvp failed");
    }

    return 1; // Todo: ハンドリングの追加/エラーメッセージの追加
}

// OCI `create` command
void create_container(const CreateOptions& options) {
    const std::string& id = options.id;
    const std::string requested_bundle = options.bundle.empty() ? "." : options.bundle;
    const std::string bundle_path = resolve_absolute_path(requested_bundle);

    if (id.empty()) {
        std::cerr << "Error: Container id is required." << std::endl;
        return;
    }

    if (options.no_pivot) {
        std::cerr << "Warning: --no-pivot is not supported; ignoring request." << std::endl;
    }
    if (options.preserve_fds > 0) {
        std::cerr << "Warning: --preserve-fds is not supported; ignoring request." << std::endl;
    }
    if (!options.notify_socket.empty()) {
        std::cerr << "Warning: --notify-socket is not supported; ignoring request." << std::endl;
    }

    OCIConfig config;
    try {
        config = load_config(bundle_path);
    } catch (const std::exception& e) {
        std::cerr << "Error processing config file: " << e.what() << std::endl;
        return;
    }

    ContainerState state;
    state.oci_version = config.ociVersion;
    state.version = config.ociVersion.empty() ? RUNTIME_VERSION : config.ociVersion;
    state.id = id;
    state.pid = 0;
    state.status = "creating";
    state.bundle_path = bundle_path;
    state.annotations = config.annotations;
    state.annotations["runway.version"] = RUNTIME_VERSION;
    bool fifo_created = false;
    bool state_saved = false;
    pid_t pid = -1;
    std::string cgroup_relative_path;
    ConsolePair console_pair;
    bool console_allocated = false;
    std::string container_dir = state_base_path() + id;
    std::string fifo_path = get_fifo_path(id);

    auto cleanup_failure = [&](const std::string& phase, const std::string& message = "") {
        if (!message.empty()) {
            std::cerr << message << std::endl;
        }
        if (pid > 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
        if (!cgroup_relative_path.empty()) {
            cleanup_cgroups(id, cgroup_relative_path);
        }
        if (fifo_created) {
            unlink(fifo_path.c_str());
        }
        if (state_saved) {
            std::string state_file_path = container_dir + "/state.json";
            unlink(state_file_path.c_str());
        }
        rmdir(container_dir.c_str());
        close_console_pair(console_pair);
        json event_data = json{{"phase", phase}};
        if (!message.empty()) {
            event_data["message"] = message;
        }
        record_event(id, "error", event_data);
    };

    if (mkdir(container_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        perror("Failed to create container directory"); return;
    }

    record_state_event(state);

    if (!run_hook_sequence(config.hooks.create_runtime, state, "createRuntime")) {
        cleanup_failure("createRuntime", "createRuntime hooks failed");
        return;
    }

    if (mkfifo(fifo_path.c_str(), 0666) == -1 && errno != EEXIST) {
        perror("mkfifo failed");
        cleanup_failure("create", "Failed to create container FIFO");
        return;
    }
    fifo_created = true;

    std::unique_ptr<ContainerArgs> args(new ContainerArgs());
    args->sync_fifo_path = fifo_path;
    std::string rootfs_path = config.root.path;
    if (!rootfs_path.empty() && rootfs_path.front() != '/') {
        rootfs_path = bundle_path + "/" + rootfs_path;
    }
    args->rootfs_path = resolve_absolute_path(rootfs_path);
    args->hostname = config.hostname.empty() ? id : config.hostname;
    args->rootfs_readonly = config.root.readonly;
    args->enable_pivot_root = !options.no_pivot;
    args->mounts = config.mounts;
    for (auto& mount_cfg : args->mounts) {
        if (!mount_cfg.source.empty() && mount_cfg.source.front() != '/') {
            mount_cfg.source = bundle_path + "/" + mount_cfg.source;
        }
    }
    args->masked_paths = config.linux.masked_paths;
    args->readonly_paths = config.linux.readonly_paths;
    args->rootfs_propagation = config.linux.rootfs_propagation;
    args->process_args = config.process.args;
    args->process_env = config.process.env;
    args->process_cwd = config.process.cwd.empty() ? "/" : config.process.cwd;
    args->terminal = config.process.terminal;
    if (args->terminal) {
        if (options.console_socket.empty()) {
            cleanup_failure("console", "process.terminal requires --console-socket");
            return;
        }
        std::string console_error;
        if (!allocate_console_pair(console_pair, console_error)) {
            cleanup_failure("console", console_error);
            return;
        }
        console_allocated = true;
        args->console_slave_fd = console_pair.slave_fd;
    } else if (!options.console_socket.empty()) {
        std::cerr << "Warning: --console-socket specified but process.terminal is false; ignoring console socket." << std::endl;
    }

    if (args->process_args.empty()) {
        cleanup_failure("validation", "Error: process.args must contain at least one entry.");
        return;
    }

    int flags = SIGCHLD;
    bool creates_new_userns = false;
    std::map<std::string, int> ns_map = {
            {"pid", CLONE_NEWPID}, {"uts", CLONE_NEWUTS}, {"ipc", CLONE_NEWIPC},
            {"net", CLONE_NEWNET}, {"mnt", CLONE_NEWNS}, {"user", CLONE_NEWUSER},
            {"cgroup", CLONE_NEWCGROUP}
    };

    for (const auto& ns : config.linux.namespaces) {
        auto it = ns_map.find(ns.type);
        if (it == ns_map.end()) {
            continue;
        }
        int ns_flag = it->second;
        if (!ns.path.empty()) {
            int fd = open(ns.path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                perror(("Failed to open namespace path: " + ns.path).c_str());
                cleanup_failure("namespace", "Failed to open namespace path: " + ns.path);
                return;
            }
            args->join_namespaces.emplace_back(fd, ns_flag);
            continue;
        }
        flags |= ns_flag;
        if (ns_flag == CLONE_NEWUSER) {
            creates_new_userns = true;
        }
    }

    std::vector<LinuxIDMapping> uid_mappings = config.linux.uid_mappings;
    std::vector<LinuxIDMapping> gid_mappings = config.linux.gid_mappings;
    if (creates_new_userns) {
        if (uid_mappings.empty()) {
            LinuxIDMapping map{};
            map.container_id = 0;
            map.host_id = static_cast<uint32_t>(getuid());
            map.size = 1;
            uid_mappings.push_back(map);
        }
        if (gid_mappings.empty()) {
            LinuxIDMapping map{};
            map.container_id = 0;
            map.host_id = static_cast<uint32_t>(getgid());
            map.size = 1;
            gid_mappings.push_back(map);
        }
    }

    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    pid = clone(container_main, stack_top, flags, args.get());
    delete[] stack;

    if (pid == -1) {
        perror("clone failed");
        cleanup_failure("clone", "Failed to clone container process");
        return;
    }
    if (!configure_user_namespace(pid, creates_new_userns, uid_mappings, gid_mappings)) {
        cleanup_failure("userNamespace", "Failed to configure user namespace");
        return;
    }
    args.release();

    if (console_allocated && console_pair.slave_fd >= 0) {
        close(console_pair.slave_fd);
        console_pair.slave_fd = -1;
    }
    if (console_allocated) {
        std::string console_error;
        if (!send_console_fd(console_pair, options.console_socket, console_error)) {
            cleanup_failure("consoleSocket", console_error);
            return;
        }
        if (console_pair.master_fd >= 0) {
            close(console_pair.master_fd);
            console_pair.master_fd = -1;
        }
        console_allocated = false;
    }

    // Cgroupの設定系
    try {
        setup_cgroups(pid, id, config.linux, cgroup_relative_path);
    } catch (const std::exception& e) {
        cleanup_failure("cgroup", std::string("Error setting up cgroups: ") + e.what());
        return;
    }
    // ここまで

    state.pid = pid;
    state.status = "created";
    if (!cgroup_relative_path.empty()) {
        state.annotations["runway.cgroupPath"] = cgroup_relative_path;
    }
    if (!run_hook_sequence(config.hooks.create_container, state, "createContainer")) {
        cleanup_failure("createContainer", "createContainer hooks failed");
        return;
    }

    if (!save_state(state)) {
        cleanup_failure("state", "Failed to save container state");
        return;
    }
    state_saved = true;

    record_state_event(state);

    if (!options.pid_file.empty()) {
        if (!write_pid_file(options.pid_file, pid)) {
            cleanup_failure("pidFile", "Failed to write pid file: " + options.pid_file);
            return;
        }
    }

    log_debug("Container '" + id + "' created with PID " + std::to_string(pid));
}

bool parse_create_options(int argc, char* const argv[], CreateOptions& options) {
    static struct option create_long_options[] = {
            {"bundle", required_argument, nullptr, 'b'},
            {"pid-file", required_argument, nullptr, 'p'},
            {"console-socket", required_argument, nullptr, 'c'},
            {"no-pivot", no_argument, nullptr, 'n'},
            {"notify-socket", required_argument, nullptr, 'N'},
            {"preserve-fds", required_argument, nullptr, 'P'},
            {nullptr, 0, nullptr, 0}
    };

    opterr = 0;
    optind = 1;

    int option;
    while ((option = getopt_long(argc, argv, "+", create_long_options, nullptr)) != -1) {
        switch (option) {
            case 'b':
                options.bundle = optarg;
                break;
            case 'p':
                options.pid_file = optarg;
                break;
            case 'c':
                options.console_socket = optarg;
                break;
            case 'n':
                options.no_pivot = true;
                break;
            case 'N':
                options.notify_socket = optarg;
                break;
            case 'P':
                try {
                    options.preserve_fds = std::stoi(optarg);
                } catch (const std::exception&) {
                    std::cerr << "Invalid value for --preserve-fds: " << optarg << std::endl;
                    optind = 1;
                    return false;
                }
                break;
            case '?': {
                int idx = std::max(0, optind - 1);
                std::cerr << "Unknown create option: " << argv[idx] << std::endl;
                optind = 1;
                return false;
            }
            default:
                std::cerr << "Unknown create option encountered." << std::endl;
                optind = 1;
                return false;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: Container id is required." << std::endl;
        optind = 1;
        return false;
    }

    options.id = argv[optind];
    if (optind + 1 < argc) {
        std::cerr << "Error: Unexpected argument: " << argv[optind + 1] << std::endl;
        optind = 1;
        return false;
    }

    optind = 1;
    return true;
}

bool parse_exec_options(int argc, char* const argv[], ExecOptions& options) {
    static struct option exec_long_options[] = {
            {"process", required_argument, nullptr, 'p'},
            {"pid-file", required_argument, nullptr, 'f'},
            {"detach", no_argument, nullptr, 'd'},
            {"tty", no_argument, nullptr, 't'},
            {"preserve-fds", required_argument, nullptr, 'F'},
            {nullptr, 0, nullptr, 0}
    };

    opterr = 0;
    optind = 1;

    int option;
    while ((option = getopt_long(argc, argv, "+", exec_long_options, nullptr)) != -1) {
        switch (option) {
            case 'p':
                options.process_path = optarg;
                break;
            case 'f':
                options.pid_file = optarg;
                break;
            case 'd':
                options.detach = true;
                break;
            case 't':
                options.tty = true;
                break;
            case 'F':
                try {
                    options.preserve_fds = std::stoi(optarg);
                } catch (const std::exception&) {
                    std::cerr << "Invalid value for --preserve-fds: " << optarg << std::endl;
                    optind = 1;
                    return false;
                }
                break;
            case '?': {
                int idx = std::max(0, optind - 1);
                std::cerr << "Unknown exec option: " << argv[idx] << std::endl;
                optind = 1;
                return false;
            }
            default:
                std::cerr << "Unknown exec option encountered." << std::endl;
                optind = 1;
                return false;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: Container id is required." << std::endl;
        optind = 1;
        return false;
    }
    options.id = argv[optind++];
    for (int i = optind; i < argc; ++i) {
        options.args.emplace_back(argv[i]);
    }

    optind = 1;
    return true;
}

bool parse_events_options(int argc, char* const argv[], EventsOptions& options) {
    static struct option events_long_options[] = {
            {"follow", no_argument, nullptr, 'f'},
            {"stats", no_argument, nullptr, 's'},
            {"interval", required_argument, nullptr, 'i'},
            {nullptr, 0, nullptr, 0}
    };

    opterr = 0;
    optind = 1;

    int option;
    while ((option = getopt_long(argc, argv, "+", events_long_options, nullptr)) != -1) {
        switch (option) {
            case 'f':
                options.follow = true;
                break;
            case 's':
                options.stats = true;
                break;
            case 'i':
                try {
                    options.interval_ms = std::stoi(optarg);
                    if (options.interval_ms <= 0) {
                        options.interval_ms = 1000;
                    }
                } catch (const std::exception&) {
                    std::cerr << "Invalid value for --interval: " << optarg << std::endl;
                    optind = 1;
                    return false;
                }
                break;
            case '?': {
                int idx = std::max(0, optind - 1);
                std::cerr << "Unknown events option: " << argv[idx] << std::endl;
                optind = 1;
                return false;
            }
            default:
                std::cerr << "Unknown events option encountered." << std::endl;
                optind = 1;
                return false;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: Container id is required." << std::endl;
        optind = 1;
        return false;
    }
    options.id = argv[optind++];
    if (optind < argc) {
        std::cerr << "Error: Unexpected argument: " << argv[optind] << std::endl;
        optind = 1;
        return false;
    }

    optind = 1;
    return true;
}

void start_container(const std::string& id, bool attach);
int exec_container(const ExecOptions& options);
void pause_container(const std::string& id);
void resume_container(const std::string& id);
void list_container_processes(const std::string& id);
void delete_container(const std::string& id, bool force);
void events_command(const EventsOptions& options);

int run_container_command(int argc, char* const argv[]) {
    CreateOptions options;
    if (!parse_create_options(argc, argv, options)) {
        return 1;
    }

    create_container(options);

    ContainerState state;
    try {
        state = load_state(options.id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    if (state.status != "created") {
        std::cerr << "Error: Container is not in 'created' state (current: "
                  << state.status << ")" << std::endl;
        return 1;
    }

    start_container(options.id, false);

    int status = 0;
    if (waitpid(state.pid, &status, 0) == -1) {
        perror("waitpid failed");
        return 1;
    }

    state.status = "stopped";
    save_state(state);

    delete_container(options.id, false);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 1;
}

// OCI `start` command
void start_container(const std::string& id, bool attach) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }

    if (state.status != "created") {
        std::cerr << "Error: Container is not in 'created' state (current: " << state.status << ")" << std::endl;
        return;
    }

    const std::string bundle_path = state.bundle_path.empty() ? "." : state.bundle_path;
    OCIConfig config;
    try {
        config = load_config(bundle_path);
    } catch (const std::exception& e) {
        std::cerr << "Error loading config for container '" << id << "': " << e.what() << std::endl;
        record_event(id, "error", json{{"phase", "config"}, {"message", e.what()}});
        return;
    }

    auto fail_with_event = [&](const std::string& phase, const std::string& message) {
        if (!message.empty()) {
            std::cerr << message << std::endl;
        }
        json data = {{"phase", phase}};
        if (!message.empty()) {
            data["message"] = message;
        }
        record_event(id, "error", data);
    };

    if (!run_hook_sequence(config.hooks.prestart, state, "prestart")) {
        fail_with_event("prestart", "prestart hooks failed");
        return;
    }
    if (!run_hook_sequence(config.hooks.start_container, state, "startContainer")) {
        fail_with_event("startContainer", "startContainer hooks failed");
        return;
    }

    std::string fifo_path = get_fifo_path(id);
    int fifo_fd = open(fifo_path.c_str(), O_WRONLY);
    if (fifo_fd == -1) {
        perror("Failed to open FIFO (write)");
        fail_with_event("start", "Failed to open FIFO for container start");
        return;
    }

    if (write(fifo_fd, "1", 1) != 1) {
        perror("Failed to write to FIFO");
        close(fifo_fd);
        fail_with_event("start", "Failed to signal container start");
        return;
    }
    close(fifo_fd);

    state.status = "running";
    if (!run_hook_sequence(config.hooks.poststart, state, "poststart")) {
        fail_with_event("poststart", "poststart hooks failed");
        if (state.pid > 0) {
            kill(state.pid, SIGKILL);
            waitpid(state.pid, nullptr, 0);
        }
        state.status = "stopped";
        save_state(state);
        record_state_event(state);
        return;
    }

    if (!save_state(state)) {
        fail_with_event("state", "Failed to persist running state");
        return;
    }
    record_state_event(state);
    log_debug("Container '" + id + "' started.");

    if (attach) {
        log_debug("Attaching to container (PID: " + std::to_string(state.pid) + ")...");

        while (true) {
            if (kill(state.pid, 0) != 0) {
                if (errno == ESRCH) {
                    log_debug("Container '" + id + "' has exited.");
                    state.status = "stopped";
                    save_state(state);
                    record_state_event(state);
                    break;
                }
                perror("Error checking container status");
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

int exec_container(const ExecOptions& options) {
    if (options.tty) {
        std::cerr << "Warning: --tty is not supported; ignoring request." << std::endl;
    }
    if (options.preserve_fds > 0) {
        std::cerr << "Warning: --preserve-fds is not supported; ignoring request." << std::endl;
    }

    ContainerState state;
    try {
        state = load_state(options.id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    if (state.status != "running") {
        std::cerr << "Error: Container must be running to exec (current: " << state.status << ")" << std::endl;
        return 1;
    }

    const std::string bundle_path = state.bundle_path.empty() ? "." : state.bundle_path;
    OCIConfig config;
    try {
        config = load_config(bundle_path);
    } catch (const std::exception& e) {
        std::cerr << "Error loading container config: " << e.what() << std::endl;
        return 1;
    }

    ProcessConfig process_cfg;
    bool process_specified = false;

    if (!options.process_path.empty()) {
        std::ifstream ifs(options.process_path);
        if (!ifs) {
            std::cerr << "Error: Unable to open process spec file: " << options.process_path << std::endl;
            return 1;
        }
        try {
            json j;
            ifs >> j;
            process_cfg = j.get<ProcessConfig>();
            process_specified = true;
        } catch (const std::exception& e) {
            std::cerr << "Error parsing process spec: " << e.what() << std::endl;
            return 1;
        }
    }

    if (!process_specified) {
        if (options.args.empty()) {
            std::cerr << "Error: command arguments are required when --process is not provided." << std::endl;
            return 1;
        }
        process_cfg.args = options.args;
    }

    if (process_cfg.args.empty()) {
        std::cerr << "Error: process args must not be empty." << std::endl;
        return 1;
    }

    if (process_cfg.cwd.empty()) {
        process_cfg.cwd = config.process.cwd.empty() ? "/" : config.process.cwd;
    }
    if (process_cfg.env.empty()) {
        process_cfg.env = config.process.env;
    }

    const std::vector<std::string> namespace_order = {"user", "mnt", "pid", "ipc", "uts", "net", "cgroup"};
    std::vector<int> namespace_fds;
    namespace_fds.reserve(namespace_order.size());
    std::string pid_str = std::to_string(state.pid);
    for (const auto& ns_name : namespace_order) {
        std::string ns_path = "/proc/" + pid_str + "/ns/" + ns_name;
        int fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            if (errno == ENOENT) {
                continue;
            }
            perror(("Failed to open namespace " + ns_name).c_str());
            for (int existing_fd : namespace_fds) {
                close(existing_fd);
            }
            return 1;
        }
        namespace_fds.push_back(fd);
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork failed");
        for (int fd : namespace_fds) {
            close(fd);
        }
        return 1;
    }

    if (child == 0) {
        for (int fd : namespace_fds) {
            if (setns(fd, 0) != 0) {
                perror("setns failed");
                _exit(1);
            }
        }
        for (int fd : namespace_fds) {
            close(fd);
        }

        if (!process_cfg.cwd.empty()) {
            if (chdir(process_cfg.cwd.c_str()) != 0) {
                perror("Failed to change working directory for exec");
                _exit(1);
            }
        }

        if (!process_cfg.env.empty()) {
            if (clearenv() != 0) {
                perror("clearenv failed for exec");
                _exit(1);
            }
            for (const auto& env_entry : process_cfg.env) {
                std::size_t eq_pos = env_entry.find('=');
                std::string key = env_entry.substr(0, eq_pos);
                std::string value = (eq_pos == std::string::npos) ? "" : env_entry.substr(eq_pos + 1);
                if (key.empty()) {
                    continue;
                }
                if (setenv(key.c_str(), value.c_str(), 1) != 0) {
                    perror("setenv failed for exec");
                    _exit(1);
                }
            }
        }

        std::vector<char*> argv;
        argv.reserve(process_cfg.args.size() + 1);
        for (auto& arg : process_cfg.args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        if (execvp(argv[0], argv.data()) != 0) {
            perror("execvp failed for exec");
            _exit(127);
        }
        _exit(127);
    }

    for (int fd : namespace_fds) {
        close(fd);
    }

    if (!options.pid_file.empty()) {
        if (!write_pid_file(options.pid_file, child)) {
            std::cerr << "Warning: Failed to write exec pid file: " << options.pid_file << std::endl;
        }
    }

    json event_data = {
            {"pid", child},
            {"args", join_strings(process_cfg.args, " ")}
    };
    record_event(options.id, "exec", event_data);

    if (options.detach) {
        return 0;
    }

    int status = 0;
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid failed for exec");
        record_event(options.id, "error", json{{"phase", "exec"}, {"message", "waitpid failed"}});
        return 1;
    }

    json exit_event = {
            {"pid", child}
    };
    int exit_code = 1;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        exit_event["type"] = "exit";
        exit_event["status"] = exit_code;
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
        exit_event["type"] = "signal";
        exit_event["status"] = exit_code;
    }
    record_event(options.id, "execExit", exit_event);
    return exit_code;
}

std::vector<pid_t> collect_process_tree(pid_t root_pid) {
    std::vector<pid_t> result;
    if (root_pid <= 0) {
        return result;
    }
    std::queue<pid_t> queue;
    std::set<pid_t> visited;
    queue.push(root_pid);
    visited.insert(root_pid);

    while (!queue.empty()) {
        pid_t current = queue.front();
        queue.pop();
        result.push_back(current);

        std::string children_path = "/proc/" + std::to_string(current) + "/task/" +
                                    std::to_string(current) + "/children";
        std::ifstream ifs(children_path);
        if (!ifs) {
            continue;
        }
        pid_t child = 0;
        while (ifs >> child) {
            if (child > 0 && visited.insert(child).second) {
                queue.push(child);
            }
        }
    }
    return result;
}

void pause_container(const std::string& id) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }

    if (state.status == "paused") {
        std::cerr << "Container '" << id << "' is already paused." << std::endl;
        return;
    }
    if (state.status != "running") {
        std::cerr << "Error: Container must be running to pause (current: " << state.status << ")" << std::endl;
        return;
    }

    std::vector<pid_t> pids = collect_process_tree(state.pid);
    bool failed = false;
    for (pid_t pid : pids) {
        if (kill(pid, SIGSTOP) != 0 && errno != ESRCH) {
            perror(("Failed to pause pid " + std::to_string(pid)).c_str());
            failed = true;
        }
    }
    if (failed) {
        record_event(id, "error", json{{"phase", "pause"}, {"message", "Failed to pause all processes"}});
        return;
    }

    state.status = "paused";
    if (!save_state(state)) {
        std::cerr << "Warning: Failed to persist paused state." << std::endl;
    }
    record_state_event(state);
    log_debug("Container '" + id + "' paused.");
}

void resume_container(const std::string& id) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }

    if (state.status != "paused") {
        std::cerr << "Error: Container is not paused (current: " << state.status << ")" << std::endl;
        return;
    }

    std::vector<pid_t> pids = collect_process_tree(state.pid);
    bool failed = false;
    for (pid_t pid : pids) {
        if (kill(pid, SIGCONT) != 0 && errno != ESRCH) {
            perror(("Failed to resume pid " + std::to_string(pid)).c_str());
            failed = true;
        }
    }
    if (failed) {
        record_event(id, "error", json{{"phase", "resume"}, {"message", "Failed to resume all processes"}});
        return;
    }

    state.status = "running";
    if (!save_state(state)) {
        std::cerr << "Warning: Failed to persist running state after resume." << std::endl;
    }
    record_state_event(state);
    log_debug("Container '" + id + "' resumed.");
}

void list_container_processes(const std::string& id) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }

    if (state.pid <= 0) {
        std::cerr << "Container '" << id << "' has no active init pid." << std::endl;
        return;
    }

    std::vector<pid_t> pids = collect_process_tree(state.pid);
    if (pids.empty()) {
        std::cout << "No processes found for container '" << id << "'." << std::endl;
        return;
    }
    std::sort(pids.begin(), pids.end());
    std::cout << "PID\tCMD" << std::endl;
    for (pid_t pid : pids) {
        std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream ifs(comm_path);
        std::string cmd;
        if (ifs) {
            std::getline(ifs, cmd);
        }
        if (cmd.empty()) {
            cmd = "?";
        }
        std::cout << pid << '\t' << cmd << std::endl;
    }
}

static bool collect_proc_stats(pid_t pid, json& out_stats) {
    if (pid <= 0) {
        return false;
    }

    std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream stat_file(stat_path);
    if (!stat_file) {
        return false;
    }
    std::string line;
    std::getline(stat_file, line);
    auto end_paren = line.rfind(')');
    if (end_paren == std::string::npos || end_paren + 2 >= line.size()) {
        return false;
    }
    std::string after = line.substr(end_paren + 2);
    std::istringstream iss(after);
    std::string token;
    for (int i = 0; i < 11; ++i) {
        if (!(iss >> token)) {
            return false;
        }
    }
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    if (!(iss >> utime >> stime)) {
        return false;
    }
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    unsigned long long total_ns = 0;
    if (ticks_per_second > 0) {
        unsigned long long total_ticks = utime + stime;
        total_ns = (total_ticks * 1000000000ULL) / static_cast<unsigned long long>(ticks_per_second);
    }

    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream status_file(status_path);
    unsigned long long rss_bytes = 0;
    if (status_file) {
        std::string status_line;
        while (std::getline(status_file, status_line)) {
            if (status_line.rfind("VmRSS:", 0) == 0) {
                std::istringstream rss_stream(status_line.substr(6));
                unsigned long long rss_kb = 0;
                rss_stream >> rss_kb;
                rss_bytes = rss_kb * 1024ULL;
                break;
            }
        }
    }

    std::vector<pid_t> tree = collect_process_tree(pid);
    json cpu_usage = {
            {"total", total_ns}
    };
    json memory_usage = {
            {"rss", rss_bytes}
    };
    out_stats = json{
            {"timestamp", iso8601_now()},
            {"cpu", {{"usage", cpu_usage}}},
            {"memory", {{"usage", memory_usage}}},
            {"pids", {{"current", static_cast<uint64_t>(tree.size())}}}
    };
    return true;
}

void events_command(const EventsOptions& options) {
    ContainerState state;
    bool has_state = true;
    try {
        state = load_state(options.id);
    } catch (const std::exception&) {
        has_state = false;
    }

    if (options.stats) {
        if (!has_state) {
            std::cerr << "Error: Unable to load container state; cannot collect stats." << std::endl;
            return;
        }
        if (state.pid <= 0) {
            std::cerr << "Error: Container has no active pid for stats collection." << std::endl;
            return;
        }
        pid_t target_pid = state.pid;
        while (true) {
            json stats;
            if (!collect_proc_stats(target_pid, stats)) {
                std::cerr << "Failed to collect stats for pid " << target_pid << std::endl;
                return;
            }
            json event = {
                    {"timestamp", iso8601_now()},
                    {"type", "stats"},
                    {"id", options.id},
                    {"data", stats}
            };
            std::cout << event.dump() << std::endl;
            if (!options.follow) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
            if (kill(target_pid, 0) != 0 && errno == ESRCH) {
                break;
            }
        }
        return;
    }

    std::string events_path = events_file_path(options.id);
    std::ifstream events(events_path);
    if (!events) {
        std::cerr << "No events found for container '" << options.id << "'." << std::endl;
        return;
    }

    std::string line;
    while (std::getline(events, line)) {
        if (line.empty()) {
            continue;
        }
        json entry = json::parse(line, nullptr, false);
        if (entry.is_discarded()) {
            std::cout << line << std::endl;
        } else {
            std::cout << entry.dump() << std::endl;
        }
    }

    if (!options.follow) {
        return;
    }

    events.clear();
    while (true) {
        if (std::getline(events, line)) {
            if (line.empty()) {
                continue;
            }
            json entry = json::parse(line, nullptr, false);
            if (entry.is_discarded()) {
                std::cout << line << std::endl;
            } else {
                std::cout << entry.dump() << std::endl;
            }
            continue;
        }
        if (!events.good()) {
            events.clear();
        }

        if (has_state && state.pid > 0) {
            if (kill(state.pid, 0) != 0 && errno == ESRCH) {
                // Container has exited; check if file still exists before exiting.
                std::ifstream check(events_path);
                if (!check) {
                    break;
                }
            }
        } else {
            std::ifstream check(events_path);
            if (!check) {
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
    }
}
// OCI `state` command
void show_state(const std::string& id) {
    try {
        ContainerState state = load_state(id);
        if (state.pid != -1 && kill(state.pid, 0) != 0 && errno == ESRCH) {
            if (state.status != "stopped") {
                state.status = "stopped";
                save_state(state);
            }
        }
        std::cout << state.to_json() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

// OCI `kill` command
void kill_container(const std::string& id, int signal) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "running" && state.status != "created") {
        std::cerr << "Error: Container is not running or created." << std::endl;
        return;
    }

    if (kill(state.pid, signal) == 0) {
        log_debug("Sent signal " + std::to_string(signal) + " to process " + std::to_string(state.pid));
        record_event(id, "signal", json{{"signal", signal}});
        if (signal == SIGKILL || signal == SIGTERM) {
            while (waitpid(state.pid, NULL, 0) == -1) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            state.status = "stopped";
            if (!save_state(state)) {
                std::cerr << "Failed to persist stopped state for container '" << id << "'" << std::endl;
            }
            record_state_event(state);
            log_debug("Container '" + id + "' is stopped.");
        }
    } else {
        perror("kill failed");
        record_event(id, "error", json{{"phase", "signal"}, {"message", "kill failed"}});
    }
}

// OCI `delete` command
void delete_container(const std::string& id, bool force) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    bool process_running = (state.pid != -1 && kill(state.pid, 0) == 0);

    if (process_running && force) {
        if (kill(state.pid, SIGKILL) != 0 && errno != ESRCH) {
            perror("Failed to force terminate container process");
            return;
        }
        waitpid(state.pid, NULL, 0);
        process_running = false;
    }

    if (state.status != "stopped") {
        if (process_running) {
            std::cerr << "Error: Container is still running. Kill it first." << std::endl;
            return;
        }
        state.status = "stopped";
        if (!save_state(state)) {
            std::cerr << "Warning: Failed to persist stopped state before delete." << std::endl;
        }
    }

    bool hooks_loaded = false;
    OCIConfig config;
    if (!state.bundle_path.empty()) {
        try {
            config = load_config(state.bundle_path);
            hooks_loaded = true;
        } catch (const std::exception& e) {
            std::cerr << "Warning: Unable to reload config for delete: " << e.what() << std::endl;
        }
    }

    if (hooks_loaded) {
        if (!run_hook_sequence(config.hooks.poststop, state, "poststop")) {
            record_event(id, "error", json{{"phase", "poststop"}, {"message", "poststop hooks failed"}});
            return;
        }
        if (!save_state(state)) {
            std::cerr << "Warning: Failed to persist poststop annotations." << std::endl;
        }
    }

    std::string container_path = state_base_path() + id;
    std::string state_file = container_path + "/state.json";
    std::string fifo_file = get_fifo_path(id);
    std::string events_file = events_file_path(id);

    unlink(fifo_file.c_str());
    if (remove(state_file.c_str()) != 0) {
        perror("Failed to delete state file");
    }
    unlink(events_file.c_str());
    if (rmdir(container_path.c_str()) != 0) {
        perror("Failed to delete state directory");
    }

    std::string cgroup_path_hint;
    auto it = state.annotations.find("runway.cgroupPath");
    if (it != state.annotations.end()) {
        cgroup_path_hint = it->second;
    }

    cleanup_cgroups(id, cgroup_path_hint);

    log_debug("Container '" + id + "' deleted.");
}

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [global options] <command> [arguments]\n"
              << "\n"
              << "Global options:\n"
              << "  --debug                 Enable verbose debug logging (accepted only)\n"
              << "  --log <path>            Write runtime logs to the given file\n"
              << "  --log-format <fmt>      Log format (text|json)\n"
              << "  --root <path>           Path to the runtime state directory\n"
              << "  --systemd-cgroup        Accept systemd cgroup requests (not yet implemented)\n"
              << "  --help                  Show this help message\n"
              << "  --version               Show version information\n"
              << "\n"
              << "Commands:\n"
              << "  create [options] <id>   Create a container\n"
              << "  run [options] <id>      Create, start, and wait on a container\n"
              << "  start  [--attach] <id>  Start a created container\n"
              << "  state  <id>             Show the state of a container\n"
              << "  exec  [options] <id>    Execute a process inside a running container\n"
              << "  pause <id>              Pause all processes in a running container\n"
              << "  resume <id>             Resume a paused container\n"
              << "  ps    <id>              List processes inside a container\n"
              << "  events [options] <id>   Stream container events or stats\n"
              << "  kill   <id> [signal]    Send a signal to a container (default: SIGTERM)\n"
              << "  delete [--force] <id>   Delete a stopped container\n"
              << "\n"
              << "create options:\n"
              << "  --bundle <path>         Set the OCI bundle directory (default: current directory)\n"
              << "  --pid-file <path>       Write the container init PID to the file\n"
              << "  --console-socket <path> Accepted for compatibility but ignored\n"
              << "\n"
              << "exec options:\n"
              << "  --process <path>        Read process spec (process.json format)\n"
              << "  --pid-file <path>       Write the exec process PID to file\n"
              << "  --detach                Start the process without waiting for exit\n"
              << "  --tty                   Accepted for compatibility but ignored\n"
              << "  --preserve-fds <n>      Accepted for compatibility but ignored\n"
              << "\n"
              << "events options:\n"
              << "  --follow                Stream events until container exit\n"
              << "  --stats                 Emit periodic stats instead of event log\n"
              << "  --interval <ms>         Poll interval for --follow/--stats (default: 1000)\n"
              << "Run accepts the same options as create.\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    g_global_options.root_path = default_state_root();
    opterr = 0;
    optind = 1;

    static struct option global_long_options[] = {
            {"debug", no_argument, nullptr, OPT_DEBUG},
            {"log", required_argument, nullptr, OPT_LOG},
            {"log-format", required_argument, nullptr, OPT_LOG_FORMAT},
            {"root", required_argument, nullptr, OPT_ROOT},
            {"version", no_argument, nullptr, OPT_VERSION},
            {"help", no_argument, nullptr, OPT_HELP},
            {"systemd-cgroup", no_argument, nullptr, OPT_SYSTEMD_CGROUP},
            {nullptr, 0, nullptr, 0}
    };

    int global_opt;
    while ((global_opt = getopt_long(argc, argv, "+", global_long_options, nullptr)) != -1) {
        switch (global_opt) {
            case OPT_DEBUG:
                g_global_options.debug = true;
                break;
            case OPT_LOG:
                g_global_options.log_path = optarg;
                if (!configure_log_destination(g_global_options.log_path)) {
                    return 1;
                }
                break;
            case OPT_LOG_FORMAT:
                g_global_options.log_format = optarg;
                if (g_global_options.log_format != "text" && g_global_options.log_format != "json") {
                    std::cerr << "Warning: Unsupported log format '" << g_global_options.log_format
                              << "', defaulting to text." << std::endl;
                    g_global_options.log_format = "text";
                }
                break;
            case OPT_ROOT:
                g_global_options.root_path = optarg ? optarg : "";
                while (g_global_options.root_path.size() > 1 && g_global_options.root_path.back() == '/') {
                    g_global_options.root_path.pop_back();
                }
                if (g_global_options.root_path.empty()) {
                    g_global_options.root_path = "/";
                }
                break;
            case OPT_VERSION:
                std::cout << "Container Runway version " << RUNTIME_VERSION << std::endl;
                return 0;
            case OPT_HELP:
                print_usage(argv[0]);
                return 0;
            case OPT_SYSTEMD_CGROUP:
                g_global_options.systemd_cgroup = true;
                break;
            case '?': {
                int idx = std::max(0, optind - 1);
                std::cerr << "Unknown global option: " << argv[idx] << std::endl;
                print_usage(argv[0]);
                return 1;
            }
            default:
                std::cerr << "Unknown option encountered." << std::endl;
                return 1;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    char** command_argv = argv + optind;
    int command_argc = argc - optind;
    std::string command = command_argv[0];

    if (!ensure_runtime_root_directory()) {
        return 1;
    }

    if (command == "create") {
        CreateOptions create_opts;
        if (!parse_create_options(command_argc, command_argv, create_opts)) {
            return 1;
        }
        create_container(create_opts);
    } else if (command == "run") {
        return run_container_command(command_argc, command_argv);
    } else if (command == "start") {
        bool attach = false;
        std::string id;
        for (int i = 1; i < command_argc; ++i) {
            std::string arg = command_argv[i];
            if (arg == "-a" || arg == "--attach") {
                attach = true;
                continue;
            }
            if (arg.rfind("-", 0) == 0) {
                std::cerr << "Unknown start option: " << arg << std::endl;
                return 1;
            }
            id = arg;
            if (i + 1 < command_argc) {
                std::cerr << "Error: Unexpected argument: " << command_argv[i + 1] << std::endl;
                return 1;
            }
            break;
        }
        if (id.empty()) {
            std::cerr << "Error: Container id is required." << std::endl;
            return 1;
        }
        start_container(id, attach);
    } else if (command == "state") {
        if (command_argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        show_state(command_argv[1]);
    } else if (command == "exec") {
        ExecOptions exec_opts;
        if (!parse_exec_options(command_argc, command_argv, exec_opts)) {
            return 1;
        }
        return exec_container(exec_opts);
    } else if (command == "pause") {
        if (command_argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        pause_container(command_argv[1]);
        return 0;
    } else if (command == "resume") {
        if (command_argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        resume_container(command_argv[1]);
        return 0;
    } else if (command == "ps") {
        if (command_argc != 2) {
            print_usage(argv[0]);
            return 1;
        }
        list_container_processes(command_argv[1]);
        return 0;
    } else if (command == "events") {
        EventsOptions events_opts;
        if (!parse_events_options(command_argc, command_argv, events_opts)) {
            return 1;
        }
        events_command(events_opts);
        return 0;
    } else if (command == "kill") {
        if (command_argc < 2 || command_argc > 3) {
            print_usage(argv[0]);
            return 1;
        }
        int sig = SIGTERM;
        if (command_argc == 3) {
            try {
                sig = std::stoi(command_argv[2]);
            } catch (const std::exception&) {
                std::cerr << "Invalid signal value: " << command_argv[2] << std::endl;
                return 1;
            }
        }
        kill_container(command_argv[1], sig);
    } else if (command == "delete") {
        bool force = false;
        std::string id;
        for (int i = 1; i < command_argc; ++i) {
            std::string arg = command_argv[i];
            if (arg == "--force" || arg == "-f") {
                force = true;
                continue;
            }
            if (arg.rfind("-", 0) == 0) {
                std::cerr << "Unknown delete option: " << arg << std::endl;
                return 1;
            }
            id = arg;
            if (i + 1 < command_argc) {
                std::cerr << "Error: Unexpected argument: " << command_argv[i + 1] << std::endl;
                return 1;
            }
            break;
        }
        if (id.empty()) {
            std::cerr << "Error: Container id is required." << std::endl;
            return 1;
        }
        delete_container(id, force);
    } else {
        std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
