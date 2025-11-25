#pragma once

#include <sys/types.h>
#include <vector>

bool wait_for_process(pid_t pid, int timeout_sec, int& status);
std::vector<pid_t> collect_process_tree(pid_t root_pid);
