#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <grp.h>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <map>
#include <memory>
#include <sched.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "runtime/config.h"
#include "runtime/console.h"
#include "runtime/filesystem.h"
#include "runtime/hooks.h"
#include "runtime/isolation.h"
#include "runtime/options.h"
#include "runtime/process.h"
#include "runtime/state.h"

constexpr int STACK_SIZE = 1024 * 1024; // 1MB

enum GlobalOptionValue {
    OPT_DEBUG = 1000,
    OPT_LOG,
    OPT_LOG_FORMAT,
    OPT_ROOT,
    OPT_VERSION,
    OPT_HELP,
    OPT_SYSTEMD_CGROUP
};



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
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::vector<uint32_t> additional_gids;
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

// Entry point for the child process (container)
// This runs after fork() + unshare(), so C++ stdlib is safe to use
int container_main(void* arg) {
    ContainerArgs* args = static_cast<ContainerArgs*>(arg);

    // join_namespaces already handled in parent's child process before calling this

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
            // Ignore EBUSY errors for cgroup mounts - already mounted by Docker
            if (errno == EBUSY && (destination.find("cgroup") != std::string::npos ||
                                   (fs_type && std::string(fs_type).find("cgroup") != std::string::npos))) {
                // Already mounted, continue
            } else {
                perror(("Failed to mount " + destination).c_str());
                return 1;
            }
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
                    // Skip if creation fails (e.g., in /proc)
                    continue;
                }
            } else if (!ensure_file(target) && !ensure_directory(target)) {
                // Skip if creation fails (e.g., in /proc)
                continue;
            }
        }
        if (mount(target.c_str(), target.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
            // Ignore mount failures - some paths may not be mountable
            continue;
        }
        if (mount(nullptr, target.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_REC | MS_RDONLY, nullptr) != 0) {
            // Ignore remount failures
            continue;
        }
    }

    bool pivot_succeeded = false;
    if (args->enable_pivot_root) {
        // pivot_root requires the new root to be a mount point
        // We already bind-mounted it, but we need to ensure it's a distinct mountpoint
        // Remount to make it a proper mountpoint
        if (mount(".", ".", nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            const std::string old_root_dir = ".runway-oldroot";
            if (!ensure_directory(old_root_dir, 0700)) {
                // Directory creation failed, skip pivot_root
            } else if (syscall(SYS_pivot_root, ".", old_root_dir.c_str()) != 0) {
                // pivot_root failed, will fallback to chroot (silent)
            } else {
                pivot_succeeded = true;
                if (chdir("/") != 0) {
                    perror("chdir to new root failed");
                    return 1;
                }
                if (umount2(("/" + old_root_dir).c_str(), MNT_DETACH) != 0) {
                    // Unmount failures are not fatal
                }
                if (rmdir(("/" + old_root_dir).c_str()) != 0) {
                    // Cleanup failures are not fatal
                }
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

    // Apply masked paths AFTER /proc is mounted
    for (const auto& masked : args->masked_paths) {
        if (masked.empty()) {
            continue;
        }
        // Use absolute path after pivot/chroot
        std::string target = masked;
        if (target.front() != '/') {
            target = "/" + target;
        }

        struct stat st{};
        bool is_dir = false;
        if (lstat(target.c_str(), &st) == 0) {
            is_dir = S_ISDIR(st.st_mode);
        } else {
            // Path doesn't exist - try to create it
            if (masked.back() == '/') {
                if (!ensure_directory(target)) {
                    // Skip if we can't create it (e.g., in /proc)
                    continue;
                }
                is_dir = true;
            } else if (ensure_file(target)) {
                is_dir = false;
            } else if (ensure_directory(target)) {
                is_dir = true;
            } else {
                // Can't create, skip
                continue;
            }
        }

        if (is_dir) {
            if (mount("tmpfs", target.c_str(), "tmpfs",
                      MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                      "size=0") != 0) {
                // Ignore mount failures for masked paths
                continue;
            }
        } else {
            if (mount("/dev/null", target.c_str(), nullptr, MS_BIND, nullptr) != 0) {
                // Ignore mount failures for masked paths
                continue;
            }
        }
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

    // Create essential device nodes
    struct DeviceNode {
        const char* path;
        mode_t mode;
        unsigned int major;
        unsigned int minor;
    };

    const DeviceNode devices[] = {
        {"/dev/null", S_IFCHR | 0666, 1, 3},
        {"/dev/zero", S_IFCHR | 0666, 1, 5},
        {"/dev/full", S_IFCHR | 0666, 1, 7},
        {"/dev/random", S_IFCHR | 0666, 1, 8},
        {"/dev/urandom", S_IFCHR | 0666, 1, 9},
        {"/dev/tty", S_IFCHR | 0666, 5, 0}
    };

    for (const auto& dev : devices) {
        dev_t device = makedev(dev.major, dev.minor);
        if (mknod(dev.path, dev.mode, device) != 0 && errno != EEXIST) {
            // Ignore errors for devices that already exist or can't be created
        } else if (errno != EEXIST) {
            chmod(dev.path, dev.mode & 0777);
        }
    }

    // Set UID/GID if specified
    if (!args->additional_gids.empty()) {
        if (setgroups(args->additional_gids.size(),
                      reinterpret_cast<const gid_t*>(args->additional_gids.data())) != 0) {
            perror("setgroups failed");
            return 1;
        }
    }
    if (args->gid != 0) {
        if (setgid(args->gid) != 0) {
            perror("setgid failed");
            return 1;
        }
    }
    if (args->uid != 0) {
        if (setuid(args->uid) != 0) {
            perror("setuid failed");
            return 1;
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

    return 1;
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
    args->uid = config.process.uid;
    args->gid = config.process.gid;
    args->additional_gids = config.process.additional_gids;
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

    // Use fork() instead of clone() to avoid C++ stdlib issues
    pid = fork();

    if (pid == -1) {
        perror("fork failed");
        cleanup_failure("fork", "Failed to fork container process");
        return;
    }

    if (pid == 0) {
        // Child process: setup namespaces then run container_main logic

        // Release unique_ptr ownership in child process only
        // fork() has created a proper copy of memory for us
        ContainerArgs* args_ptr = args.release();

        // Join existing namespaces first
        for (auto& ns_fd : args_ptr->join_namespaces) {
            if (setns(ns_fd.first, ns_fd.second) != 0) {
                perror("setns failed");
                _exit(1);
            }
            close(ns_fd.first);
        }
        args_ptr->join_namespaces.clear();

        // Create new namespaces using unshare
        int unshare_flags = 0;
        if (flags & CLONE_NEWPID) unshare_flags |= CLONE_NEWPID;
        if (flags & CLONE_NEWUTS) unshare_flags |= CLONE_NEWUTS;
        if (flags & CLONE_NEWIPC) unshare_flags |= CLONE_NEWIPC;
        if (flags & CLONE_NEWNET) unshare_flags |= CLONE_NEWNET;
        if (flags & CLONE_NEWNS) unshare_flags |= CLONE_NEWNS;
        if (flags & CLONE_NEWUSER) unshare_flags |= CLONE_NEWUSER;
        if (flags & CLONE_NEWCGROUP) unshare_flags |= CLONE_NEWCGROUP;

        if (unshare_flags != 0) {
            if (unshare(unshare_flags) != 0) {
                perror("unshare failed");
                _exit(1);
            }
        }

        // If we created a PID namespace, we need to fork again
        // so the child becomes PID 1 in the new namespace
        if (flags & CLONE_NEWPID) {
            pid_t inner_pid = fork();
            if (inner_pid == -1) {
                perror("fork for PID namespace failed");
                _exit(1);
            }
            if (inner_pid != 0) {
                // Middle process: wait for inner child then cleanup and exit
                // We must delete args_ptr here before exiting
                int status;
                waitpid(inner_pid, &status, 0);
                delete args_ptr;
                if (WIFEXITED(status)) {
                    _exit(WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    _exit(128 + WTERMSIG(status));
                }
                _exit(1);
            }
            // Inner child is now PID 1 in the new PID namespace
        }

        // Now run container_main logic
        int result = container_main(static_cast<void*>(args_ptr));
        _exit(result);
    }

    // Parent process: continue setup
    // args unique_ptr is still valid here and will be cleaned up automatically
    // when this function returns. fork() created a copy of memory for child.

    // Close namespace file descriptors in parent
    for (auto& ns_fd : args->join_namespaces) {
        close(ns_fd.first);
    }
    args->join_namespaces.clear();

    if (!configure_user_namespace(pid, creates_new_userns, uid_mappings, gid_mappings)) {
        cleanup_failure("userNamespace", "Failed to configure user namespace");
        return;
    }

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

    // Send signal to the process and all its children
    if (kill(state.pid, signal) == 0) {
        log_debug("Sent signal " + std::to_string(signal) + " to process " + std::to_string(state.pid));
        record_event(id, "signal", json{{"signal", signal}});

        // For termination signals, just mark as stopped
        // Don't wait - the process may be in a PID namespace and we can't wait for it
        if (signal == SIGKILL || signal == SIGTERM) {
            state.status = "stopped";
            if (!save_state(state)) {
                std::cerr << "Failed to persist stopped state for container '" << id << "'" << std::endl;
            }
            record_state_event(state);
            log_debug("Container '" + id + "' is stopped.");
        }
    } else {
        // If kill failed, check if process is already dead
        if (errno == ESRCH) {
            state.status = "stopped";
            save_state(state);
            record_state_event(state);
        } else {
            perror("kill failed");
            record_event(id, "error", json{{"phase", "signal"}, {"message", "kill failed"}});
        }
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

void show_features() {
    json features = {
        {"ociVersionMin", "1.0.0"},
        {"ociVersionMax", "1.1.0"},
        {"hooks", json::array({"prestart", "createRuntime", "createContainer",
                               "startContainer", "poststart", "poststop"})},
        {"mountOptions", json::array({"bind", "rbind", "ro", "rw", "nosuid", "nodev",
                                      "noexec", "relatime", "private", "shared", "slave"})},
        {"linux", {
            {"namespaces", json::array({"pid", "network", "ipc", "uts", "mount", "user", "cgroup"})},
            {"capabilities", json::array()},
            {"cgroup", {
                {"v1", true},
                {"v2", true},
                {"systemd", false},
                {"systemdUser", false}
            }},
            {"seccomp", {
                {"enabled", false},
                {"actions", json::array()},
                {"operators", json::array()},
                {"archs", json::array()}
            }},
            {"apparmor", {
                {"enabled", false}
            }},
            {"selinux", {
                {"enabled", false}
            }}
        }},
        {"annotations", {
            {"runway.version", RUNTIME_VERSION},
            {"org.opencontainers.runtime-spec.features", "1.1.0"}
        }}
    };
    std::cout << features.dump(2) << std::endl;
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
              << "  features                Show supported OCI runtime features\n"
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
    } else if (command == "features") {
        show_features();
        return 0;
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
