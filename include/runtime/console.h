#pragma once

#include <string>

struct ConsolePair {
    int master_fd = -1;
    int slave_fd = -1;
    std::string slave_name;
};

void close_console_pair(ConsolePair& pair);
bool allocate_console_pair(ConsolePair& pair, std::string& error_message);
bool send_console_fd(const ConsolePair& pair, const std::string& socket_path, std::string& error_message);
