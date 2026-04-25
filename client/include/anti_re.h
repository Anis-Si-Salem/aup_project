#pragma once

#include <thread>
#include <atomic>
#include <string>
#include <cstdint>

namespace anti_re {

void init();
void start_background_monitor();
void stop_background_monitor();

bool check_tracer_pid();
bool check_ptrace();
bool check_breakpoint();
bool check_timing();
bool check_maps_integrity();
bool check_binary_integrity();
bool check_text_checksum();
bool check_heartbeat();

void set_expected_checksum(uint64_t checksum);
uint64_t compute_text_checksum();

bool check_license_expiry();
void set_license_expiry(uint64_t expiry_timestamp);

struct stealth_config {
    std::atomic<bool> running{false};
    std::thread monitor_thread;
    std::atomic<uint32_t> violation_count{0};
    std::atomic<bool> terminated{false};
    std::atomic<uint64_t> heartbeat{0};
    std::atomic<uint64_t> expected_checksum{0};
    std::atomic<uint64_t> license_expiry{0};
};

stealth_config& get_config();

}