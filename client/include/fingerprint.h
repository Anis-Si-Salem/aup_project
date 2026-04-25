#pragma once

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

#define SHA256_DIGEST_LENGTH 32

namespace fingerprint {

struct hardware_ids {
    std::string tpm_ek;
    std::string tpm_ek_hash;
    bool tpm_available;
    bool tpm_required;  // If true, license REQUIRES TPM (non-negotiable)
    std::string machine_id;
    std::string product_uuid;
    std::string cpu_info;
    std::vector<std::pair<std::string, std::string>> macs;
};

hardware_ids collect_all();
std::string compute_hash(const hardware_ids& ids);
std::string compute_fingerprint_hash();
hardware_ids get_current_hardware();

}