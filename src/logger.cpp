#include "logger.hpp"
#include <iostream>
#include <fstream>
#include <ctime>

static std::ofstream g_log_file;

void init_logger() {
    time_t now = time(nullptr);
    char path[64];
    strftime(path, sizeof(path), "/var/log/edr-%Y-%m-%d_%H-%M-%S.log", localtime(&now));
    g_log_file.open(path, std::ios::app);
}

void log_msg(const std::string& msg) {
    std::cout << msg << std::endl;
    if (g_log_file.is_open())
        g_log_file << msg << std::endl;
}
