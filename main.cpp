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
#include <dirent.h>
#include <system_error>

#include "json.hpp"

// A convenient alias for nlohmann::json
using json = nlohmann::json;

constexpr int STACK_SIZE = 1024 * 1024; // 1MB

// Base directory to save state files
const std::string STATE_BASE_PATH = "/run/mruntime/";
// Base path for cgroups
const std::string CGROUP_BASE_PATH = "/sys/fs/cgroup/";

// --- C++ structs corresponding to the config.json structure ---

struct ProcessConfig {
    bool terminal;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd;
};

struct RootConfig {
    std::string path;
    bool readonly;
};

struct LinuxNamespaceConfig {
    std::string type;
    std::string path;
};

// Cgroup向けのコンフィグ設定
struct LinuxResourcesConfig {
    long long memory_limit = 0; // memory.limit_in_bytes
    long long cpu_shares = 0;   // cpu.shares
};

struct LinuxConfig {
    std::vector<LinuxNamespaceConfig> namespaces;
    LinuxResourcesConfig resources;
};

// config Jsonのパース用構造
struct OCIConfig {
    std::string ociVersion;
    RootConfig root;
    ProcessConfig process;
    std::string hostname;
    LinuxConfig linux;
};

// --- JSONファイルの読み込み ---

void from_json(const json& j, ProcessConfig& p) {
    j.at("args").get_to(p.args);
    j.at("cwd").get_to(p.cwd);
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
    return STATE_BASE_PATH + container_id + "/sync_fifo";
}

// Struct to hold arguments for the container
struct ContainerArgs {
    char** argv;
    std::string sync_fifo_path;
    std::string rootfs_path;
    std::string hostname;
    bool rootfs_readonly;
};

// Struct to represent the container's state
struct ContainerState {
    std::string id;
    pid_t pid = -1;
    std::string status; // creating, created, running, stopped
    std::string bundle_path;

    std::string to_json() const {
        json j = {
                {"id", id},
                {"pid", pid},
                {"status", status},
                {"bundle_path", bundle_path}
        };
        return j.dump(4);
    }

    static ContainerState from_json(const std::string& json_str) {
        ContainerState state;
        json j = json::parse(json_str);
        j.at("id").get_to(state.id);
        j.at("pid").get_to(state.pid);
        j.at("status").get_to(state.status);
        j.at("bundle_path").get_to(state.bundle_path);
        return state;
    }
};

bool save_state(const ContainerState& state) {
    std::string container_path = STATE_BASE_PATH + state.id;
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
    std::string state_file_path = STATE_BASE_PATH + container_id + "/state.json";
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

// Helper to write to a cgroup file
void write_cgroup_file(const std::string& path, const std::string& value) {
    std::ofstream ofs(path);
    if (!ofs) {
        throw std::runtime_error("Failed to open cgroup file: " + path);
    }
    ofs << value;
}

//seccomp系アタッチ
//void attach_bpf(pid_t pid, int& syscalls[], bool isActive){
//    //Todo: BPF処理を外部実装
//}

// 制限のアタッチ
void setup_cgroups(pid_t pid, const std::string& id, const LinuxResourcesConfig& resources) {
    std::cout << "Setting up cgroups for container " << id << std::endl;

    // Memory Cgroup
    if (resources.memory_limit > 0) {
        std::string mem_cgroup_path = CGROUP_BASE_PATH + "memory/my_runtime/" + id;
        if (mkdir((CGROUP_BASE_PATH + "memory/my_runtime").c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::system_error(errno, std::system_category(), "Failed to create base memory cgroup dir");
        }
        if (mkdir(mem_cgroup_path.c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::system_error(errno, std::system_category(), "Failed to create memory cgroup dir");
        }
        write_cgroup_file(mem_cgroup_path + "/memory.limit_in_bytes", std::to_string(resources.memory_limit));
        write_cgroup_file(mem_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }

    // CPU Cgroup
    if (resources.cpu_shares > 0) {
        std::string cpu_cgroup_path = CGROUP_BASE_PATH + "cpu/my_runtime/" + id;
        if (mkdir((CGROUP_BASE_PATH + "cpu/my_runtime").c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::system_error(errno, std::system_category(), "Failed to create base cpu cgroup dir");
        }
        if (mkdir(cpu_cgroup_path.c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::system_error(errno, std::system_category(), "Failed to create cpu cgroup dir");
        }
        write_cgroup_file(cpu_cgroup_path + "/cpu.shares", std::to_string(resources.cpu_shares));
        write_cgroup_file(cpu_cgroup_path + "/cgroup.procs", std::to_string(pid));
    }
}

// Cleans up cgroups for the container
void cleanup_cgroups(const std::string& id) {
    std::cout << "Cleaning up cgroups for container " << id << std::endl;
    std::string mem_cgroup_path = CGROUP_BASE_PATH + "memory/my_runtime/" + id;
    if (rmdir(mem_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove memory cgroup dir: " + mem_cgroup_path).c_str());
    }
    std::string cpu_cgroup_path = CGROUP_BASE_PATH + "cpu/my_runtime/" + id;
    if (rmdir(cpu_cgroup_path.c_str()) != 0 && errno != ENOENT) {
        perror(("Failed to remove cpu cgroup dir: " + cpu_cgroup_path).c_str());
    }
}


// Entry point for the child process (container)
int container_main(void* arg) {
    ContainerArgs* args = static_cast<ContainerArgs*>(arg);

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
        perror("sethostname failed"); return 1;
    }
    if (chdir(args->rootfs_path.c_str()) != 0) {
        perror("chdir to rootfs failed"); return 1;
    }
    if (chroot(".") != 0) {
        perror("chroot failed"); return 1;
    }
    if (chdir("/") != 0) {
        perror("chdir to / failed"); return 1;
    }
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("Failed to mount proc");
    }
    if (args->rootfs_readonly) {
        if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL) != 0) {
            perror("Failed to remount rootfs as readonly");
        }
    }

    // 3. Execute the specified command
    if (execvp(args->argv[0], args->argv)) {
        perror("execvp failed");
    }

    return 1; // Todo: ハンドリングの追加/エラーメッセージの追加
}

// OCI `create` command
void create_container(const std::string& id, const std::string& bundle_path) {
    OCIConfig config;
    try {
        config = load_config(bundle_path);
    } catch (const std::exception& e) {
        std::cerr << "Error processing config file: " << e.what() << std::endl;
        return;
    }

    std::string container_dir = STATE_BASE_PATH + id;
    if (mkdir(container_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        perror("Failed to create container directory"); return;
    }

    std::string fifo_path = get_fifo_path(id);
    if (mkfifo(fifo_path.c_str(), 0666) == -1 && errno != EEXIST) {
        perror("mkfifo failed"); return;
    }

    ContainerArgs args;
    args.sync_fifo_path = fifo_path;
    args.rootfs_path = bundle_path + "/" + config.root.path;
    args.hostname = config.hostname;
    args.rootfs_readonly = config.root.readonly;

    std::vector<char*> argv_vec;
    for (const auto& arg_str : config.process.args) {
        argv_vec.push_back(const_cast<char*>(arg_str.c_str()));
    }
    argv_vec.push_back(nullptr);
    args.argv = argv_vec.data();

    int flags = SIGCHLD;
    std::map<std::string, int> ns_map = {
            {"pid", CLONE_NEWPID}, {"uts", CLONE_NEWUTS}, {"ipc", CLONE_NEWIPC},
            {"net", CLONE_NEWNET}, {"mnt", CLONE_NEWNS}, {"user", CLONE_NEWUSER},
            {"cgroup", CLONE_NEWCGROUP}
    };
    for (const auto& ns : config.linux.namespaces) {
        if (ns_map.count(ns.type)) {
            flags |= ns_map[ns.type];
        }
    }

    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    pid_t pid = clone(container_main, stack_top, flags, &args);
    delete[] stack;

    if (pid == -1) {
        perror("clone failed");
        unlink(fifo_path.c_str());
        return;
    }

    // Cgroupの設定系
    try {
        setup_cgroups(pid, id, config.linux.resources);
    } catch (const std::exception& e) {
        std::cerr << "Error setting up cgroups: " << e.what() << std::endl;
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        cleanup_cgroups(id);
        unlink(fifo_path.c_str());
        rmdir(container_dir.c_str());
        return;
    }
    // ここまで

    ContainerState state;
    state.id = id;
    state.pid = pid;
    state.status = "created";
    state.bundle_path = bundle_path;

    if (!save_state(state)) {
        std::cerr << "Failed to save state." << std::endl;
        kill(pid, SIGKILL);
        cleanup_cgroups(id); //不正なCgroupの削除
    } else {
        std::cout << "Container '" << id << "' created. Status: created, PID: " << pid << std::endl;
    }
}

// OCI `start` command
void start_container(const std::string& id, bool attach) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "created") {
        std::cerr << "Error: Container is not in 'created' state (current: " << state.status << ")" << std::endl;
        return;
    }

    std::string fifo_path = get_fifo_path(id);
    int fifo_fd = open(fifo_path.c_str(), O_WRONLY);
    if (fifo_fd == -1) {
        perror("Failed to open FIFO (write)");
        return;
    }

    if (write(fifo_fd, "1", 1) != 1) {
        perror("Failed to write to FIFO");
        close(fifo_fd);
        return;
    }
    close(fifo_fd);

    state.status = "running";
    save_state(state);
    std::cout << "Container '" << id << "' started." << std::endl;

    if (attach) {
        std::cout << "Attaching to container (PID: " << state.pid << ")..." << std::endl;

        while (true) {
            // Check if the process is still running
            if (kill(state.pid, 0) != 0) {
                if (errno == ESRCH) {
                    // Process no longer exists
                    std::cout << "Container '" << id << "' has exited." << std::endl;
                    state.status = "stopped";
                    save_state(state);
                    break;
                } else {
                    perror("Error checking container status");
                    break;
                }
            }
            // Sleep briefly to avoid busy-waiting
            usleep(100000); // 100ms
        }
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
        std::cout << "Sent signal " << signal << " to process " << state.pid << std::endl;
        if (signal == SIGKILL || signal == SIGTERM) {
            waitpid(state.pid, NULL, 0);
            state.status = "stopped";
            save_state(state);
            std::cout << "Container '" << id << "' is stopped." << std::endl;
        }
    } else {
        perror("kill failed");
    }
}

// OCI `delete` command
void delete_container(const std::string& id) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "stopped") {
        if (state.pid != -1 && kill(state.pid, 0) == 0) {
            std::cerr << "Error: Container is still running. Kill it first." << std::endl;
            return;
        }
        state.status = "stopped";
        save_state(state);
    }

    std::string container_path = STATE_BASE_PATH + id;
    std::string state_file = container_path + "/state.json";
    std::string fifo_file = get_fifo_path(id);

    unlink(fifo_file.c_str());
    if (remove(state_file.c_str()) != 0) {
        perror("Failed to delete state file");
    }
    if (rmdir(container_path.c_str()) != 0) {
        perror("Failed to delete state directory");
    }

    cleanup_cgroups(id);

    std::cout << "Container '" << id << "' deleted." << std::endl;
}

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <command> [args...]\n"
              << "\n"
              << "Commands:\n"
              << "  create <id> <bundle-path>      Create a container\n"
              << "  start  [-a|--attach] <id>      Start a created container\n"
              << "                                 -a, --attach: Attach to the container for interactive use\n"
              << "  state  <id>                    Show the state of a container\n"
              << "  kill   <id> [signal]           Send a signal to a container (default: SIGTERM)\n"
              << "  delete <id>                    Delete a stopped container\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (getuid() != 0) {
        std::cerr << "Error: This program must be run as root." << std::endl;
        return 1;
    }

    mkdir(STATE_BASE_PATH.c_str(), 0755);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "create") {
        if (argc != 4) { print_usage(argv[0]); return 1; }
        create_container(argv[2], argv[3]);
    } else if (command == "start") {
        bool attach = false;
        std::string id;
        if (argc == 3) {
            id = argv[2];
        } else if (argc == 4) {
            std::string flag = argv[2];
            if (flag == "-a" || flag == "--attach") {
                attach = true;
                id = argv[3];
            } else {
                print_usage(argv[0]); return 1;
            }
        } else {
            print_usage(argv[0]); return 1;
        }
        start_container(id, attach);
    } else if (command == "state") {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        show_state(argv[2]);
    } else if (command == "kill") {
        if (argc < 3 || argc > 4) { print_usage(argv[0]); return 1; }
        int sig = (argc == 4) ? std::stoi(argv[3]) : SIGTERM;
        kill_container(argv[2], sig);
    } else if (command == "delete") {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        delete_container(argv[2]);
    } else {
        std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
