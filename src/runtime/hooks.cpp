#include "runtime/hooks.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "runtime/process.h"

extern char** environ;

namespace {

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

} // namespace

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
