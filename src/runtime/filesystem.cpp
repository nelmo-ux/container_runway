#include "runtime/filesystem.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "runtime/options.h"

bool ensure_directory(const std::string& path, mode_t mode) {
    if (path.empty()) {
        return false;
    }
    struct stat st {};
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

bool ensure_file(const std::string& path, mode_t mode) {
    struct stat st {};
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
    if (!path.empty() && path.front() == '/') {
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

std::string join_strings(const std::vector<std::string>& parts, const char* delimiter) {
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
    parsed.data = join_strings(data_options, ",");
    if ((parsed.flags & MS_BIND) && (parsed.flags & MS_RDONLY)) {
        parsed.bind_readonly = true;
    }
    return parsed;
}
