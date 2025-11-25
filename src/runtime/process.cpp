#include "runtime/process.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <fstream>
#include <queue>
#include <set>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

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
