#include "anti_re.h"
#include "secure_logger.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>

#ifdef __x86_64__
#include <x86intrin.h>
#endif

extern "C" char __executable_start[] asm("__executable_start");
extern "C" char _etext[] asm("_etext");

namespace anti_re {

static long raw_syscall3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long raw_syscall4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#ifndef SYS_openat
#define SYS_openat 257
#endif
#ifndef SYS_read
#define SYS_read 0
#endif
#ifndef SYS_close
#define SYS_close 3
#endif

static bool sys_read_file(const char* path, std::string& out, size_t max_len) {
    long fd = raw_syscall4(SYS_openat, 0, reinterpret_cast<long>(path), 0, 0);
    if (fd < 0) return false;

    char buf[4096];
    out.clear();
    while (true) {
        long n = raw_syscall3(SYS_read, fd, reinterpret_cast<long>(buf), sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > max_len) break;
    }
    raw_syscall3(SYS_close, fd, 0, 0);
    return !out.empty();
}

stealth_config& get_config() {
    static stealth_config cfg;
    return cfg;
}

bool check_tracer_pid() {
    std::string status;
    if (!sys_read_file("/proc/self/status", status, 65536)) return true;

    auto pos = status.find("TracerPid:");
    if (pos == std::string::npos) return false;
    long pid = 0;
    size_t start = pos + 10;
    while (start < status.size() && (status[start] == ' ' || status[start] == '\t')) start++;
    for (size_t i = start; i < status.size() && status[i] >= '0' && status[i] <= '9'; i++) {
        pid = pid * 10 + (status[i] - '0');
    }
    return pid != 0;
}

bool check_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        return true;
    }
    return false;
}

bool check_breakpoint() {
    std::string maps;
    if (!sys_read_file("/proc/self/maps", maps, 1024 * 1024)) return true;

    if (maps.find("LD_PRELOAD") != std::string::npos) return true;
    if (maps.find("frida") != std::string::npos) return true;
    if (maps.find("substrate") != std::string::npos) return true;
    if (maps.find("xposed") != std::string::npos) return true;

    const char* ld = getenv("LD_PRELOAD");
    if (ld && strlen(ld) > 0) return true;

    return false;
}

bool check_timing() {
    auto t1 = std::chrono::high_resolution_clock::now();
    volatile int sink = 0;
    for (int i = 0; i < 10000; i++) { sink += i; }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    return elapsed > 50000;
}

bool check_maps_integrity() {
    std::string maps;
    if (!sys_read_file("/proc/self/maps", maps, 1024 * 1024)) return true;

    int suspicious = 0;
    size_t pos = 0;
    while ((pos = maps.find('\n', pos)) != std::string::npos) {
        pos++;
    }
    if (maps.find("(deleted)") != std::string::npos) suspicious++;
    if (maps.find("frida") != std::string::npos) return true;
    if (maps.find("agent") != std::string::npos) return true;
    return suspicious > 5;
}

bool check_binary_integrity() {
    char exe[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) return false;
    exe[len] = '\0';

    std::string content;
    if (!sys_read_file(exe, content, 100 * 1024 * 1024)) return false;
    return content.size() > 0;
}

uint64_t compute_text_checksum() {
    uintptr_t start = reinterpret_cast<uintptr_t>(__executable_start);
    uintptr_t end = reinterpret_cast<uintptr_t>(_etext);
    if (end <= start) return 0;

    uint64_t hash = 14695981039346656037ULL;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(start);
    size_t len = end - start;
    for (size_t i = 0; i < len; i++) {
        hash ^= static_cast<uint64_t>(p[i]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

void set_expected_checksum(uint64_t checksum) {
    get_config().expected_checksum.store(checksum);
}

bool check_text_checksum() {
    uint64_t expected = get_config().expected_checksum.load();
    if (expected == 0) return false;
    uint64_t current = compute_text_checksum();
    return current != expected;
}

void set_license_expiry(uint64_t expiry_timestamp) {
    get_config().license_expiry.store(expiry_timestamp);
}

bool check_license_expiry() {
    uint64_t expiry = get_config().license_expiry.load();
    if (expiry == 0) return false;
    return static_cast<uint64_t>(time(nullptr)) >= expiry;
}

bool check_heartbeat() {
    uint64_t hb = get_config().heartbeat.load();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    uint64_t hb2 = get_config().heartbeat.load();
    return hb == hb2 && hb > 0;
}

static void monitor_loop() {
    auto& cfg = get_config();
    while (cfg.running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2 + (rand() % 3)));

        bool violation = false;
        if (check_tracer_pid()) violation = true;
        if (check_breakpoint()) violation = true;
        if (check_text_checksum()) violation = true;

        cfg.heartbeat.fetch_add(1);

        if (check_license_expiry()) {
            secure_logger::log_license("expired_during_use", false);
            cfg.terminated.store(true);
            _exit(137);
        }

        if (violation) {
            cfg.violation_count.fetch_add(1);
            if (cfg.violation_count.load() > 2) {
                cfg.terminated.store(true);
                _exit(137);
            }
        } else {
            cfg.violation_count.store(0);
        }
    }
}

void init() {
    srand(static_cast<unsigned>(time(nullptr)));
    if (check_tracer_pid() || check_breakpoint()) {
        _exit(137);
    }
    uint64_t cs = compute_text_checksum();
    set_expected_checksum(cs);
}

void start_background_monitor() {
    auto& cfg = get_config();
    cfg.running.store(true);
    cfg.monitor_thread = std::thread(monitor_loop);
    cfg.monitor_thread.detach();
}

void stop_background_monitor() {
    auto& get = get_config();
    get.running.store(false);
}

}