#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

namespace secure_logger {

void init(const std::string& fingerprint_hex);
void init(const std::string& fingerprint_hex, const std::string& log_path);

void log(const std::string& event, const std::string& detail = "");

void log_startup();
void log_hw_validation(const std::string& fp_hash, bool match);
void log_tamper(const std::string& reason);
void log_tpm(const std::string& event, bool success);
void log_license(const std::string& action, bool success);
void log_seal(const std::string& action, bool success);

void shutdown();

}