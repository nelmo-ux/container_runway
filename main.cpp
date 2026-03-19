#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <cstring>
#include <dirent.h>
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
    SeccompConfig seccomp;
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
    std::string console_socket;
    std::string cwd;
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

static std::string join_syscall_list(const std::vector<int>& syscalls) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < syscalls.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << syscalls[i];
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// Seccomp exit diagnostics
// ---------------------------------------------------------------------------

#ifndef SIGSYS
#define SIGSYS 31
#endif

/// Spawn strace attached to the given PID, writing output to log_path.
/// Returns the strace process PID (or -1 on failure).
static pid_t spawn_strace(pid_t target_pid, const std::string& log_path) {
    pid_t strace_pid = fork();
    if (strace_pid < 0) {
        perror("fork for strace failed");
        return -1;
    }
    if (strace_pid == 0) {
        // Child: exec strace
        std::string pid_str = std::to_string(target_pid);
        execlp("strace", "strace",
               "-f",            // follow forks
               "-tt",           // microsecond timestamps
               "-T",            // show time spent in syscall
               "-yy",           // decode fd paths and socket addresses
               "-o", log_path.c_str(),
               "-p", pid_str.c_str(),
               nullptr);
        perror("execlp strace failed");
        _exit(127);
    }
    // Parent: wait briefly for strace to attach
    usleep(200000); // 200ms
    // Verify strace is still alive
    int wstatus;
    pid_t ret = waitpid(strace_pid, &wstatus, WNOHANG);
    if (ret == strace_pid) {
        // strace already exited (probably failed to attach)
        std::cerr << "strace: failed to attach to PID " << target_pid << std::endl;
        return -1;
    }
    return strace_pid;
}

/// Read recent dmesg entries looking for seccomp audit lines for the given PID.
/// Returns the matching lines (may be empty if dmesg is unavailable or no match).
static std::vector<std::string> read_seccomp_audit(pid_t pid) {
    std::vector<std::string> results;
    FILE* fp = popen("dmesg --time-format iso 2>/dev/null || dmesg 2>/dev/null", "r");
    if (!fp) {
        return results;
    }
    std::string pid_str = "pid=" + std::to_string(pid);
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        std::string line(buf);
        // Kernel seccomp audit lines contain "seccomp" or "type=1326" (AUDIT_SECCOMP)
        if ((line.find("audit") != std::string::npos || line.find("seccomp") != std::string::npos)
            && line.find(pid_str) != std::string::npos) {
            // Remove trailing newline
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }
            results.push_back(line);
        }
    }
    pclose(fp);
    return results;
}

/// Describe a process exit status.  When the process was killed by SIGSYS
/// (the seccomp kill signal), emit detailed diagnostics to stderr and return
/// structured JSON data suitable for record_event().
static json describe_exit_status(int status, pid_t pid, const std::string& context) {
    json info;
    info["pid"] = pid;

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        info["type"] = "exit";
        info["status"] = code;
        return info;
    }

    if (!WIFSIGNALED(status)) {
        info["type"] = "unknown";
        info["status"] = 1;
        return info;
    }

    int sig = WTERMSIG(status);
    info["type"] = "signal";
    info["signal"] = sig;
    info["signal_name"] = strsignal(sig) ? strsignal(sig) : "unknown";
    info["status"] = 128 + sig;

    if (sig == SIGSYS) {
        info["seccomp"] = true;
        std::string msg = "[seccomp] Container process (PID " + std::to_string(pid)
                          + ") killed by SIGSYS — seccomp policy violation";

        // Try to get details from kernel audit log
        auto audit_lines = read_seccomp_audit(pid);
        if (!audit_lines.empty()) {
            json audit_json = json::array();
            for (const auto& line : audit_lines) {
                audit_json.push_back(line);
                // Try to extract syscall number from audit line
                auto pos = line.find("syscall=");
                if (pos != std::string::npos) {
                    std::string sysno_str = line.substr(pos + 8);
                    auto end = sysno_str.find_first_not_of("0123456789");
                    if (end != std::string::npos) {
                        sysno_str = sysno_str.substr(0, end);
                    }
                    if (!sysno_str.empty()) {
                        info["blocked_syscall"] = std::stoi(sysno_str);
                        msg += " (syscall=" + sysno_str + ")";
                    }
                }
            }
            info["audit"] = audit_json;
        }

        std::cerr << msg << std::endl;
        log_debug(msg);
    }

    return info;
}

static std::string normalize_oci_config_path(const SeccompConfig& seccomp) {
    std::string path = seccomp.oci_config_path.empty() ? "/.runway/seccomp.json" : seccomp.oci_config_path;
    if (path.front() != '/') {
        path.insert(path.begin(), '/');
    }
    return path;
}

static bool write_oci_seccomp_config_file(const SeccompConfig& seccomp,
                                          const std::string& full_path,
                                          std::string& error) {
    if (seccomp.oci_json.empty()) {
        error = "seccomp OCI JSON payload is missing";
        return false;
    }
    if (!ensure_parent_directory(full_path)) {
        error = "failed to create seccomp config directory for " + full_path;
        return false;
    }
    std::ofstream ofs(full_path, std::ios::trunc);
    if (!ofs) {
        error = "failed to open seccomp config file: " + full_path;
        return false;
    }
    ofs << "{\"linux\":{\"seccomp\":" << seccomp.oci_json << "}}";
    if (!ofs) {
        error = "failed to write seccomp config file: " + full_path;
        return false;
    }
    return true;
}

static bool build_exec_arguments(const std::vector<std::string>& process_args,
                                 const SeccompConfig& seccomp,
                                 std::vector<std::string>& out_args,
                                 std::string& error) {
    if (!seccomp.enabled) {
        out_args = process_args;
        return true;
    }

    if (seccomp.binary.empty()) {
        error = "seccomp enabled but seccomp.binary is empty";
        return false;
    }

    out_args.clear();
    out_args.reserve(process_args.size() + 12);

    // Use the injected static binary from /.runway/seccomp
    out_args.push_back("/.runway/seccomp/seccomp-filter");
    out_args.push_back("apply");

    if (seccomp.oci_mode) {
        out_args.push_back("--oci-config");
        out_args.push_back(normalize_oci_config_path(seccomp));
        out_args.push_back("--");
        out_args.insert(out_args.end(), process_args.begin(), process_args.end());
        return true;
    }

    if (!seccomp.policy.empty()) {
        out_args.push_back("--policy");
        out_args.push_back(seccomp.policy);
    }
    if (!seccomp.default_action.empty()) {
        out_args.push_back("--default");
        out_args.push_back(seccomp.default_action);
    }
    if (!seccomp.notify_sock.empty()) {
        out_args.push_back("--notify-sock");
        out_args.push_back(seccomp.notify_sock);
    }
    if (!seccomp.allow.empty()) {
        out_args.push_back("--allow");
        out_args.push_back(join_syscall_list(seccomp.allow));
    }
    if (!seccomp.deny.empty()) {
        out_args.push_back("--deny");
        out_args.push_back(join_syscall_list(seccomp.deny));
        if (!seccomp.deny_action.empty()) {
            out_args.push_back("--action");
            out_args.push_back(seccomp.deny_action);
        }
    }
    for (const auto& rule : seccomp.rules) {
        out_args.push_back("--rule");
        out_args.push_back(rule);
    }
    if (seccomp.errno_ret > 0) {
        out_args.push_back("--errno");
        out_args.push_back(std::to_string(seccomp.errno_ret));
    }
    if (seccomp.tsync) {
        out_args.push_back("--tsync");
    }

    out_args.push_back("--");
    out_args.insert(out_args.end(), process_args.begin(), process_args.end());
    return true;
}

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

    // Ensure mount changes stay within this namespace to avoid affecting the host.
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        perror("Failed to make mounts private");
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
            // Ignore EBUSY/EPERM errors for cgroup mounts - cgroup v2 may not allow mounting
            bool is_cgroup = (destination.find("cgroup") != std::string::npos ||
                             (fs_type && std::string(fs_type).find("cgroup") != std::string::npos));
            if (is_cgroup && (errno == EBUSY || errno == EPERM || errno == EACCES)) {
                // cgroup already mounted or not permitted, continue
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

    if (args->seccomp.enabled) {
        // Inject the statically-linked seccomp-filter binary into the rootfs
        // so it can be exec'd after pivot_root, regardless of the container's libc.
        const std::string inject_dir = "/.runway/seccomp";

        std::string host_binary = args->seccomp.binary;
        if (host_binary.find('/') == std::string::npos) {
            host_binary = "/usr/local/bin/" + host_binary;
        }

        std::string dest_binary = container_absolute_path(rootfs, inject_dir + "/seccomp-filter");
        if (!ensure_parent_directory(dest_binary)) {
            std::cerr << "Failed to create seccomp inject dir" << std::endl;
        } else {
            std::ifstream src(host_binary, std::ios::binary);
            std::ofstream dst(dest_binary, std::ios::binary | std::ios::trunc);
            if (src && dst) {
                dst << src.rdbuf();
                dst.flush();
                if (!dst.good()) {
                    std::cerr << "Warning: incomplete copy of seccomp binary to "
                              << dest_binary << std::endl;
                    dst.close();
                    unlink(dest_binary.c_str());
                } else {
                    dst.close();
                    chmod(dest_binary.c_str(), 0755);
                }
            } else {
                std::cerr << "Warning: could not copy seccomp binary from "
                          << host_binary << " to " << dest_binary << std::endl;
            }
        }

        if (args->seccomp.oci_mode) {
            std::string oci_path = normalize_oci_config_path(args->seccomp);
            std::string full_path = container_absolute_path(rootfs, oci_path);
            std::string error;
            if (!write_oci_seccomp_config_file(args->seccomp, full_path, error)) {
                std::cerr << "Failed to prepare OCI seccomp config: " << error << std::endl;
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
        int ret = mknod(dev.path, dev.mode, device);
        if (ret == 0) {
            chmod(dev.path, dev.mode & 0777);
        }
        // mknod failed: EEXIST is fine (device already exists), others are non-fatal
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

    // 3. Execute the specified command (optionally via seccomp-filter)
    std::vector<std::string> exec_args;
    std::string seccomp_error;
    if (!build_exec_arguments(args->process_args, args->seccomp, exec_args, seccomp_error)) {
        std::cerr << "Failed to build seccomp command: " << seccomp_error << std::endl;
        return 1;
    }

    std::vector<char*> argv;
    argv.reserve(exec_args.size() + 1);
    for (const auto& arg : exec_args) {
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
    args->seccomp = config.linux.seccomp;
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
            {"net", CLONE_NEWNET}, {"network", CLONE_NEWNET},
            {"mnt", CLONE_NEWNS}, {"mount", CLONE_NEWNS},
            {"user", CLONE_NEWUSER}, {"cgroup", CLONE_NEWCGROUP}
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

    // Create a pipe to communicate the real container PID from child to parent
    // This is needed because when PID namespace is used, the actual container
    // process is a grandchild, and we need its PID for exec to work correctly
    int pid_pipe[2];
    if (pipe(pid_pipe) == -1) {
        perror("pipe failed");
        cleanup_failure("pipe", "Failed to create PID communication pipe");
        return;
    }

    // Use fork() instead of clone() to avoid C++ stdlib issues
    pid = fork();

    if (pid == -1) {
        perror("fork failed");
        close(pid_pipe[0]);
        close(pid_pipe[1]);
        cleanup_failure("fork", "Failed to fork container process");
        return;
    }

    if (pid == 0) {
        // Child process: setup namespaces then run container_main logic
        close(pid_pipe[0]); // Close read end in child

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
                close(pid_pipe[1]);
                _exit(1);
            }
            if (inner_pid != 0) {
                // Middle process: send inner_pid to parent, then wait and exit
                // Write the inner child's PID to the parent
                write(pid_pipe[1], &inner_pid, sizeof(inner_pid));
                close(pid_pipe[1]);

                // Wait for inner child then cleanup and exit
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
            close(pid_pipe[1]); // Inner child doesn't need the pipe
        } else {
            // No PID namespace: write 0 to indicate parent should use first child's pid
            pid_t zero = 0;
            write(pid_pipe[1], &zero, sizeof(zero));
            close(pid_pipe[1]);
        }

        // Now run container_main logic
        int result = container_main(static_cast<void*>(args_ptr));
        _exit(result);
    }

    // Parent process: continue setup
    // args unique_ptr is still valid here and will be cleaned up automatically
    // when this function returns. fork() created a copy of memory for child.

    close(pid_pipe[1]); // Close write end in parent

    // Keep the first child's PID for user namespace setup
    pid_t first_child_pid = pid;

    // Read the real container PID from the child
    // If PID namespace is used, this will be the inner (grandchild) PID
    // If not, it will be 0 indicating we should use the first child's PID
    pid_t real_container_pid = 0;
    ssize_t n = read(pid_pipe[0], &real_container_pid, sizeof(real_container_pid));
    close(pid_pipe[0]);

    if (n == sizeof(real_container_pid) && real_container_pid != 0) {
        // Use the inner child's PID for state.pid (for PID namespace case)
        // This is the process that's actually in the new PID namespace
        pid = real_container_pid;
    }
    // else: keep pid as the first child's PID

    // Close namespace file descriptors in parent
    for (auto& ns_fd : args->join_namespaces) {
        close(ns_fd.first);
    }
    args->join_namespaces.clear();

    // User namespace setup must be done on the first child (the one that called unshare)
    if (!configure_user_namespace(first_child_pid, creates_new_userns, uid_mappings, gid_mappings)) {
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
    state.annotations["runway.childPid"] = std::to_string(first_child_pid);
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
        // Write first_child_pid to the pid-file, NOT the inner child PID.
        // containerd-shim uses this PID for waitpid(). Since first_child is
        // a direct child of the create process (reparented to the shim after
        // create exits), the shim can successfully waitpid() on it.
        // first_child itself waits for inner_child and propagates exit status.
        if (!write_pid_file(options.pid_file, first_child_pid)) {
            cleanup_failure("pidFile", "Failed to write pid file: " + options.pid_file);
            return;
        }
    }

    log_debug("Container '" + id + "' created with PID " + std::to_string(pid) +
              " (shim-visible PID " + std::to_string(first_child_pid) + ")");
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
            {"console-socket", required_argument, nullptr, 'c'},
            {"cwd", required_argument, nullptr, 'w'},
            {"detach", no_argument, nullptr, 'd'},
            {"tty", no_argument, nullptr, 't'},
            {"preserve-fds", required_argument, nullptr, 'F'},
            {"apparmor", required_argument, nullptr, 'A'},
            {"no-subreaper", no_argument, nullptr, 'S'},
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
            case 'c':
                options.console_socket = optarg;
                break;
            case 'w':
                options.cwd = optarg;
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
            case 'A': // --apparmor: accepted but ignored
            case 'S': // --no-subreaper: accepted but ignored
                break;
            case '?': {
                // Gracefully ignore unknown options with arguments
                int idx = std::max(0, optind - 1);
                std::string unknown_opt = argv[idx];
                log_debug("exec: ignoring unknown option: " + unknown_opt);
                break;
            }
            default:
                log_debug("exec: ignoring unknown option");
                break;
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
void list_containers();

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
    pid_t wait_pid = state.pid;
    auto child_it = state.annotations.find("runway.childPid");
    if (child_it != state.annotations.end()) {
        try {
            wait_pid = static_cast<pid_t>(std::stol(child_it->second));
        } catch (const std::exception&) {
            wait_pid = state.pid;
        }
    }
    if (waitpid(wait_pid, &status, 0) == -1) {
        perror("waitpid failed");
        return 1;
    }

    json exit_info = describe_exit_status(status, wait_pid, "run");
    record_event(options.id, "containerExit", exit_info);

    // Reload state to pick up strace annotations set during start
    try { state = load_state(options.id); } catch (...) {}

    // Wait for strace to finish writing
    auto strace_it = state.annotations.find("runway.stracePid");
    if (strace_it != state.annotations.end()) {
        pid_t strace_pid = static_cast<pid_t>(std::stol(strace_it->second));
        if (strace_pid > 0) {
            // strace should exit on its own when traced process dies;
            // give it a moment, then force-kill if stuck
            int strace_status;
            for (int i = 0; i < 10; i++) {
                pid_t r = waitpid(strace_pid, &strace_status, WNOHANG);
                if (r == strace_pid || (r == -1 && errno == ECHILD)) break;
                usleep(100000); // 100ms
            }
            kill(strace_pid, SIGTERM);
            waitpid(strace_pid, nullptr, WNOHANG);
        }
        auto log_it = state.annotations.find("runway.straceLog");
        if (log_it != state.annotations.end()) {
            log_debug("strace log: " + log_it->second);
        }
    }

    state.status = "stopped";
    save_state(state);

    delete_container(options.id, false);

    return exit_info.value("status", 1);
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

    // Attach strace if enabled via:
    //   1. OCI annotation: runway.strace=true
    //   2. Process env: RUNWAY_STRACE=1 (set via docker run -e RUNWAY_STRACE=1)
    pid_t strace_pid = -1;
    {
        bool strace_enabled = false;
        // Check OCI config annotations
        auto it = config.annotations.find("runway.strace");
        if (it != config.annotations.end() && !it->second.empty() && it->second != "false") {
            strace_enabled = true;
        }
        // Check state annotations (copied from config at create time)
        if (!strace_enabled) {
            auto it2 = state.annotations.find("runway.strace");
            if (it2 != state.annotations.end() && !it2->second.empty() && it2->second != "false") {
                strace_enabled = true;
            }
        }
        // Check process environment (docker run -e RUNWAY_STRACE=1)
        if (!strace_enabled) {
            for (const auto& env : config.process.env) {
                if (env == "RUNWAY_STRACE=1" || env == "RUNWAY_STRACE=true") {
                    strace_enabled = true;
                    break;
                }
            }
        }
        if (strace_enabled) {
            // Use /tmp for strace log so it persists after container deletion
            std::string short_id = id.length() > 12 ? id.substr(0, 12) : id;
            std::string strace_log = "/tmp/runway-strace-" + short_id + ".log";
            log_debug("strace: attaching to PID " + std::to_string(state.pid) +
                      ", log -> " + strace_log);
            strace_pid = spawn_strace(state.pid, strace_log);
            if (strace_pid > 0) {
                state.annotations["runway.stracePid"] = std::to_string(strace_pid);
                state.annotations["runway.straceLog"] = strace_log;
                record_event(id, "strace", json{
                    {"stracePid", strace_pid},
                    {"targetPid", state.pid},
                    {"logPath", strace_log}
                });
            } else {
                std::cerr << "strace: failed to attach (is strace installed?)" << std::endl;
            }
        }
    }

    // Persist "running" state BEFORE signaling the FIFO so that the state
    // is already on disk even if the container exits immediately.
    state.status = "running";
    if (!save_state(state)) {
        fail_with_event("state", "Failed to persist running state before start");
        if (strace_pid > 0) { kill(strace_pid, SIGTERM); waitpid(strace_pid, nullptr, 0); }
        return;
    }

    std::string fifo_path = get_fifo_path(id);
    int fifo_fd = open(fifo_path.c_str(), O_WRONLY);
    if (fifo_fd == -1) {
        perror("Failed to open FIFO (write)");
        state.status = "created";
        save_state(state);
        fail_with_event("start", "Failed to open FIFO for container start");
        if (strace_pid > 0) { kill(strace_pid, SIGTERM); waitpid(strace_pid, nullptr, 0); }
        return;
    }

    if (write(fifo_fd, "1", 1) != 1) {
        perror("Failed to write to FIFO");
        close(fifo_fd);
        state.status = "created";
        save_state(state);
        fail_with_event("start", "Failed to signal container start");
        if (strace_pid > 0) { kill(strace_pid, SIGTERM); waitpid(strace_pid, nullptr, 0); }
        return;
    }
    close(fifo_fd);

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
    if (options.preserve_fds > 0) {
        std::cerr << "Warning: --preserve-fds is not supported; ignoring request." << std::endl;
    }

    log_debug("exec_container: loading state for container '" + options.id + "'");
    log_debug("exec_container: state_base_path = '" + state_base_path() + "'");

    ContainerState state;
    try {
        state = load_state(options.id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    log_debug("exec_container: loaded state, pid = " + std::to_string(state.pid) + ", status = " + state.status);

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
    std::vector<std::pair<int, std::string>> namespace_fds;  // fd and name
    namespace_fds.reserve(namespace_order.size());

    // Use childPid (the first fork, visible from host /proc) for namespace access.
    // state.pid is the inner child which may not be accessible via /proc from the host
    // when it's in a new PID namespace.
    pid_t ns_pid = state.pid;
    auto child_it = state.annotations.find("runway.childPid");
    if (child_it != state.annotations.end()) {
        try {
            pid_t cpid = static_cast<pid_t>(std::stol(child_it->second));
            // Verify this PID is accessible
            std::string test_path = "/proc/" + std::to_string(cpid) + "/ns/pid";
            struct stat st;
            if (stat(test_path.c_str(), &st) == 0) {
                ns_pid = cpid;
            }
        } catch (...) {}
    }
    std::string pid_str = std::to_string(ns_pid);
    log_debug("exec_container: opening namespaces for pid " + pid_str);
    for (const auto& ns_name : namespace_order) {
        std::string ns_path = "/proc/" + pid_str + "/ns/" + ns_name;
        std::string self_ns_path = "/proc/self/ns/" + ns_name;

        // Check if target namespace is the same as our current namespace
        struct stat target_stat, self_stat;
        if (stat(ns_path.c_str(), &target_stat) == 0 && stat(self_ns_path.c_str(), &self_stat) == 0) {
            if (target_stat.st_ino == self_stat.st_ino && target_stat.st_dev == self_stat.st_dev) {
                log_debug("exec_container: namespace " + ns_name + " is same as current, skipping");
                continue;
            }
        }

        int fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            if (errno == ENOENT) {
                log_debug("exec_container: namespace " + ns_name + " not found, skipping");
                continue;
            }
            perror(("Failed to open namespace " + ns_name).c_str());
            for (auto& ns_fd : namespace_fds) {
                close(ns_fd.first);
            }
            return 1;
        }
        log_debug("exec_container: opened namespace " + ns_name + " (fd=" + std::to_string(fd) + ")");
        namespace_fds.push_back({fd, ns_name});
    }

    // Open the container root fd BEFORE forking/setns, because after joining
    // the mount namespace, /proc/<host_pid>/root is no longer accessible.
    std::string container_root = "/proc/" + pid_str + "/root";
    int root_fd = open(container_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd == -1) {
        std::cerr << "Failed to open container root " << container_root << ": "
                  << strerror(errno) << std::endl;
        for (auto& ns_fd : namespace_fds) { close(ns_fd.first); }
        return 1;
    }

    // Allocate PTY if terminal is requested (via --tty CLI flag or process.terminal in JSON)
    // and --console-socket is specified
    bool need_terminal = options.tty || process_cfg.terminal;
    ConsolePair console_pair;
    bool console_allocated = false;
    if (need_terminal && !options.console_socket.empty()) {
        std::string console_error;
        if (!allocate_console_pair(console_pair, console_error)) {
            std::cerr << "Failed to allocate console for exec: " << console_error << std::endl;
            close(root_fd);
            for (auto& ns_fd : namespace_fds) { close(ns_fd.first); }
            return 1;
        }
        console_allocated = true;
        log_debug("exec_container: allocated PTY pair, master_fd=" + std::to_string(console_pair.master_fd)
                  + " slave_fd=" + std::to_string(console_pair.slave_fd));
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork failed");
        close(root_fd);
        for (auto& ns_fd : namespace_fds) {
            close(ns_fd.first);
        }
        if (console_allocated) close_console_pair(console_pair);
        return 1;
    }

    if (child == 0) {
        // Child: close master side of PTY (parent sends it via console-socket)
        if (console_allocated && console_pair.master_fd >= 0) {
            close(console_pair.master_fd);
        }

        for (auto& ns_fd : namespace_fds) {
            if (setns(ns_fd.first, 0) != 0) {
                std::cerr << "setns failed for " << ns_fd.second << ": " << strerror(errno) << std::endl;
                _exit(1);
            }
        }
        for (auto& ns_fd : namespace_fds) {
            close(ns_fd.first);
        }

        // Use the pre-opened root fd to fchdir + chroot into the container rootfs
        if (fchdir(root_fd) != 0) {
            perror("fchdir to container root failed");
            close(root_fd);
            _exit(1);
        }
        close(root_fd);
        if (chroot(".") != 0) {
            perror("chroot to container root failed");
            _exit(1);
        }

        // After chroot, we need to chdir to avoid being outside the new root
        std::string cwd_path = process_cfg.cwd.empty() ? "/" : process_cfg.cwd;
        if (!options.cwd.empty()) {
            cwd_path = options.cwd;
        }
        if (chdir(cwd_path.c_str()) != 0) {
            perror("Failed to change working directory for exec");
            _exit(1);
        }

        // Set up PTY slave as stdin/stdout/stderr if console was allocated
        if (console_allocated && console_pair.slave_fd >= 0) {
            // Set default window size before connecting terminal
            struct winsize ws = {};
            ws.ws_row = 24;
            ws.ws_col = 80;
            ioctl(console_pair.slave_fd, TIOCSWINSZ, &ws);

            // Create new session and set controlling terminal
            setsid();
            if (ioctl(console_pair.slave_fd, TIOCSCTTY, 0) == -1) {
                perror("ioctl TIOCSCTTY failed");
                // Non-fatal, continue
            }
            dup2(console_pair.slave_fd, STDIN_FILENO);
            dup2(console_pair.slave_fd, STDOUT_FILENO);
            dup2(console_pair.slave_fd, STDERR_FILENO);
            if (console_pair.slave_fd > STDERR_FILENO) {
                close(console_pair.slave_fd);
            }
        }

        if (config.linux.seccomp.enabled && config.linux.seccomp.oci_mode) {
            std::string oci_path = normalize_oci_config_path(config.linux.seccomp);
            struct stat st {};
            if (stat(oci_path.c_str(), &st) != 0) {
                std::string error;
                if (!write_oci_seccomp_config_file(config.linux.seccomp, oci_path, error)) {
                    std::cerr << "Failed to prepare OCI seccomp config for exec: " << error << std::endl;
                    _exit(1);
                }
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

        std::vector<std::string> exec_args;
        std::string seccomp_error;
        if (!build_exec_arguments(process_cfg.args, config.linux.seccomp, exec_args, seccomp_error)) {
            std::cerr << "Failed to build seccomp command for exec: " << seccomp_error << std::endl;
            _exit(1);
        }

        std::vector<char*> argv;
        argv.reserve(exec_args.size() + 1);
        for (auto& arg : exec_args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        if (execvp(argv[0], argv.data()) != 0) {
            perror("execvp failed for exec");
            _exit(127);
        }
        _exit(127);
    }

    // Parent: close slave side, send master via console-socket
    close(root_fd);
    for (auto& ns_fd : namespace_fds) {
        close(ns_fd.first);
    }

    if (console_allocated) {
        // Close slave in parent
        if (console_pair.slave_fd >= 0) {
            close(console_pair.slave_fd);
            console_pair.slave_fd = -1;
        }
        // Send master fd to console-socket
        std::string console_error;
        if (!send_console_fd(console_pair, options.console_socket, console_error)) {
            std::cerr << "Failed to send console fd for exec: " << console_error << std::endl;
        }
        // Close master after sending
        if (console_pair.master_fd >= 0) {
            close(console_pair.master_fd);
            console_pair.master_fd = -1;
        }
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

    json exit_event = describe_exit_status(status, child, "exec");
    record_event(options.id, "execExit", exit_event);
    return exit_event.value("status", 1);
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
// OCI `list` command
void list_containers() {
    std::string base_path = state_base_path();
    DIR* dir = opendir(base_path.c_str());
    if (!dir) {
        // No containers exist yet or directory doesn't exist
        std::cout << "ID\tPID\tSTATUS\tBUNDLE" << std::endl;
        return;
    }

    struct ContainerInfo {
        std::string id;
        pid_t pid;
        std::string status;
        std::string bundle;
    };
    std::vector<ContainerInfo> containers;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }

        try {
            ContainerState state = load_state(name);
            // Check if process is still alive and update status if needed
            if (state.pid > 0 && state.status != "stopped") {
                if (kill(state.pid, 0) != 0 && errno == ESRCH) {
                    state.status = "stopped";
                }
            }
            ContainerInfo info;
            info.id = state.id;
            info.pid = state.pid;
            info.status = state.status;
            info.bundle = state.bundle_path;
            containers.push_back(info);
        } catch (const std::exception&) {
            // Skip directories that don't have valid state
            continue;
        }
    }
    closedir(dir);

    // Sort by container ID
    std::sort(containers.begin(), containers.end(),
              [](const ContainerInfo& a, const ContainerInfo& b) {
                  return a.id < b.id;
              });

    std::cout << "ID\tPID\tSTATUS\tBUNDLE" << std::endl;
    for (const auto& c : containers) {
        std::cout << c.id << '\t'
                  << c.pid << '\t'
                  << c.status << '\t'
                  << c.bundle << std::endl;
    }
}

// OCI `spec` command - generate default config.json
void generate_spec(const std::string& bundle_path, bool rootless) {
    std::string config_path = bundle_path + "/config.json";

    // Check if file already exists
    struct stat st;
    if (stat(config_path.c_str(), &st) == 0) {
        std::cerr << "Error: config.json already exists at " << config_path << std::endl;
        return;
    }

    json spec;
    spec["ociVersion"] = "1.0.2";

    // Root filesystem
    spec["root"] = {
        {"path", "rootfs"},
        {"readonly", false}
    };

    // Process configuration
    spec["process"] = {
        {"terminal", true},
        {"user", {
            {"uid", 0},
            {"gid", 0}
        }},
        {"args", json::array({"sh"})},
        {"env", json::array({
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        })},
        {"cwd", "/"},
        {"capabilities", {
            {"bounding", json::array({
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            })},
            {"effective", json::array({
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            })},
            {"permitted", json::array({
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            })},
            {"ambient", json::array()},
            {"inheritable", json::array()}
        }},
        {"rlimits", json::array({
            {{"type", "RLIMIT_NOFILE"}, {"hard", 1024}, {"soft", 1024}}
        })},
        {"noNewPrivileges", true}
    };

    // Hostname
    spec["hostname"] = "runway";

    // Mounts
    spec["mounts"] = json::array({
        {
            {"destination", "/proc"},
            {"type", "proc"},
            {"source", "proc"}
        },
        {
            {"destination", "/dev"},
            {"type", "tmpfs"},
            {"source", "tmpfs"},
            {"options", json::array({"nosuid", "strictatime", "mode=755", "size=65536k"})}
        },
        {
            {"destination", "/dev/pts"},
            {"type", "devpts"},
            {"source", "devpts"},
            {"options", json::array({"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"})}
        },
        {
            {"destination", "/dev/shm"},
            {"type", "tmpfs"},
            {"source", "shm"},
            {"options", json::array({"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"})}
        },
        {
            {"destination", "/dev/mqueue"},
            {"type", "mqueue"},
            {"source", "mqueue"},
            {"options", json::array({"nosuid", "noexec", "nodev"})}
        },
        {
            {"destination", "/sys"},
            {"type", "sysfs"},
            {"source", "sysfs"},
            {"options", json::array({"nosuid", "noexec", "nodev", "ro"})}
        },
        {
            {"destination", "/sys/fs/cgroup"},
            {"type", "cgroup"},
            {"source", "cgroup"},
            {"options", json::array({"nosuid", "noexec", "nodev", "relatime", "ro"})}
        }
    });

    // Linux-specific configuration
    json linux_config;

    // Namespaces
    linux_config["namespaces"] = json::array({
        {{"type", "pid"}},
        {{"type", "network"}},
        {{"type", "ipc"}},
        {{"type", "uts"}},
        {{"type", "mount"}}
    });

    if (rootless) {
        linux_config["namespaces"].push_back({{"type", "user"}});
        linux_config["uidMappings"] = json::array({
            {{"containerID", 0}, {"hostID", getuid()}, {"size", 1}}
        });
        linux_config["gidMappings"] = json::array({
            {{"containerID", 0}, {"hostID", getgid()}, {"size", 1}}
        });
    }

    // Masked paths
    linux_config["maskedPaths"] = json::array({
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/sys/firmware",
        "/proc/scsi"
    });

    // Readonly paths
    linux_config["readonlyPaths"] = json::array({
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger"
    });

    // Resources (cgroups)
    linux_config["resources"] = {
        {"devices", json::array({
            {{"allow", false}, {"access", "rwm"}}
        })}
    };

    spec["linux"] = linux_config;

    // Write the config.json file
    std::ofstream ofs(config_path);
    if (!ofs) {
        std::cerr << "Error: Failed to create " << config_path << std::endl;
        return;
    }

    ofs << spec.dump(4) << std::endl;
    ofs.close();

    std::cout << "Created " << config_path << std::endl;

    // Create rootfs directory if it doesn't exist
    std::string rootfs_path = bundle_path + "/rootfs";
    if (stat(rootfs_path.c_str(), &st) != 0) {
        if (mkdir(rootfs_path.c_str(), 0755) == 0) {
            std::cout << "Created " << rootfs_path << "/" << std::endl;
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

    // Also try to kill the first child (outer fork) if tracked
    pid_t child_pid = -1;
    auto child_it = state.annotations.find("runway.childPid");
    if (child_it != state.annotations.end()) {
        try { child_pid = static_cast<pid_t>(std::stol(child_it->second)); } catch (...) {}
    }

    // Send signal to the container init process
    if (kill(state.pid, signal) == 0) {
        log_debug("Sent signal " + std::to_string(signal) + " to process " + std::to_string(state.pid));
        record_event(id, "signal", json{{"signal", signal}});
    } else if (errno != ESRCH) {
        perror("kill failed");
        record_event(id, "error", json{{"phase", "signal"}, {"message", "kill failed"}});
    }

    // Also signal the first child process if different
    if (child_pid > 0 && child_pid != state.pid) {
        kill(child_pid, signal);
    }

    // For termination signals, wait for the process to actually die
    if (signal == SIGKILL || signal == SIGTERM) {
        pid_t wait_target = (child_pid > 0) ? child_pid : state.pid;
        bool exited = false;

        // Poll for up to 5 seconds
        for (int i = 0; i < 50; i++) {
            int wstatus;
            pid_t ret = waitpid(wait_target, &wstatus, WNOHANG);
            if (ret == wait_target || (ret == -1 && errno == ECHILD)) {
                exited = true;
                break;
            }
            // Also check if process still exists
            if (kill(state.pid, 0) == -1 && errno == ESRCH) {
                exited = true;
                break;
            }
            usleep(100000); // 100ms
        }

        if (!exited && signal == SIGTERM) {
            // Escalate to SIGKILL
            log_debug("Process did not exit after SIGTERM, sending SIGKILL");
            kill(state.pid, SIGKILL);
            if (child_pid > 0 && child_pid != state.pid) {
                kill(child_pid, SIGKILL);
            }
            // Wait another 2 seconds
            for (int i = 0; i < 20; i++) {
                int wstatus;
                pid_t ret = waitpid(wait_target, &wstatus, WNOHANG);
                if (ret == wait_target || (ret == -1 && errno == ECHILD)) {
                    exited = true;
                    break;
                }
                if (kill(state.pid, 0) == -1 && errno == ESRCH) {
                    exited = true;
                    break;
                }
                usleep(100000);
            }
        }

        state.status = "stopped";
        if (!save_state(state)) {
            std::cerr << "Failed to persist stopped state for container '" << id << "'" << std::endl;
        }
        record_state_event(state);
        log_debug("Container '" + id + "' is stopped (exited=" +
                  std::string(exited ? "true" : "false") + ").");
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

    // Also track the first child PID for cleanup
    pid_t child_pid = -1;
    auto child_it = state.annotations.find("runway.childPid");
    if (child_it != state.annotations.end()) {
        try { child_pid = static_cast<pid_t>(std::stol(child_it->second)); } catch (...) {}
    }

    bool process_running = (state.pid > 0 && kill(state.pid, 0) == 0);
    if (!process_running && child_pid > 0) {
        process_running = (kill(child_pid, 0) == 0);
    }

    if (process_running && force) {
        // Kill both container init and first child
        if (state.pid > 0) {
            kill(state.pid, SIGKILL);
        }
        if (child_pid > 0 && child_pid != state.pid) {
            kill(child_pid, SIGKILL);
        }
        // Wait for processes to die
        pid_t wait_target = (child_pid > 0) ? child_pid : state.pid;
        for (int i = 0; i < 30; i++) {
            int wstatus;
            pid_t ret = waitpid(wait_target, &wstatus, WNOHANG);
            if (ret == wait_target || (ret == -1 && errno == ECHILD)) break;
            if (kill(state.pid, 0) == -1 && errno == ESRCH) break;
            usleep(100000);
        }
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
                {"enabled", true},
                {"actions", json::array({"SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL",
                                         "SCMP_ACT_LOG", "SCMP_ACT_NOTIFY"})},
                {"operators", json::array({"SCMP_CMP_EQ", "SCMP_CMP_NE", "SCMP_CMP_LT",
                                           "SCMP_CMP_LE", "SCMP_CMP_GT", "SCMP_CMP_GE",
                                           "SCMP_CMP_MASKED_EQ"})},
                {"archs", json::array({"SCMP_ARCH_X86_64"})}
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
            {"org.opencontainers.runtime-spec.features", "1.1.0"},
            {"runway.seccomp-filter", "true"}
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
              << "  list                    List all containers\n"
              << "  spec   [options]        Generate a default OCI spec (config.json)\n"
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
              << "spec options:\n"
              << "  --bundle <path>         Generate spec in the specified directory (default: current)\n"
              << "  --rootless              Generate spec for rootless container\n"
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
    } else if (command == "list") {
        if (command_argc != 1) {
            std::cerr << "Error: list command takes no arguments." << std::endl;
            return 1;
        }
        list_containers();
        return 0;
    } else if (command == "spec") {
        std::string bundle = ".";
        bool rootless = false;
        for (int i = 1; i < command_argc; ++i) {
            std::string arg = command_argv[i];
            if (arg == "--bundle" || arg == "-b") {
                if (i + 1 >= command_argc) {
                    std::cerr << "Error: --bundle requires an argument." << std::endl;
                    return 1;
                }
                bundle = command_argv[++i];
            } else if (arg == "--rootless") {
                rootless = true;
            } else if (arg.rfind("-", 0) == 0) {
                std::cerr << "Unknown spec option: " << arg << std::endl;
                return 1;
            } else {
                std::cerr << "Error: Unexpected argument: " << arg << std::endl;
                return 1;
            }
        }
        generate_spec(bundle, rootless);
        return 0;
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
        // Parse: kill [--all] <container-id> [signal]
        // containerd-shim may pass --all to kill all processes in the container
        std::string kill_id;
        int sig = SIGTERM;
        for (int i = 1; i < command_argc; ++i) {
            std::string arg = command_argv[i];
            if (arg == "--all" || arg == "-a") {
                // Accepted but ignored (we always kill the whole process group)
                continue;
            }
            if (arg.rfind("-", 0) == 0) {
                log_debug("kill: ignoring unknown option: " + arg);
                continue;
            }
            if (kill_id.empty()) {
                kill_id = arg;
            } else {
                // Remaining positional arg is the signal
                try {
                    sig = std::stoi(arg);
                } catch (const std::exception&) {
                    std::cerr << "Invalid signal value: " << arg << std::endl;
                    return 1;
                }
            }
        }
        if (kill_id.empty()) {
            print_usage(argv[0]);
            return 1;
        }
        kill_container(kill_id, sig);
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
                // Silently ignore unknown flags from containerd-shim
                log_debug("delete: ignoring unknown option: " + arg);
                continue;
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
