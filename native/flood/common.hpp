#pragma once

#include <cstdint>
#include <string>

struct FloodStats {
    uint64_t packets_sent = 0;
    uint64_t bytes_sent = 0;
};

struct FloodConfig {
    std::string target_ip;
    uint16_t target_port = 0;
    std::string interface;
    double duration_sec = 30.0;
    double rate_limit_pps = 1000.0;  // 0 = unlimited (still capped hard in code)
};
