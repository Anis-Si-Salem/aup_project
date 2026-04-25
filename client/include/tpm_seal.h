#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace tpm_seal {

struct seal_result {
    bool success;
    std::vector<uint8_t> sealed_data;
    std::string error;
};

struct unseal_result {
    bool success;
    std::vector<uint8_t> data;
    std::string error;
};

seal_result seal_data(const std::vector<uint8_t>& data,
                      const std::string& pcr_policy);

unseal_result unseal_data(const std::vector<uint8_t>& sealed_blob);

seal_result seal_license_key(const std::vector<uint8_t>& aes_key,
                             const std::string& pcr_bank = "sha256");

unseal_result unseal_license_key(const std::vector<uint8_t>& sealed_blob,
                                  const std::string& pcr_bank = "sha256");

bool verify_pcr_integrity(const std::string& expected_pcr_hash,
                           int pcr_index = 0,
                           const std::string& pcr_bank = "sha256");

std::string get_current_pcr_hash(int pcr_index = 0,
                                  const std::string& pcr_bank = "sha256");

}