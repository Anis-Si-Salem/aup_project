#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace tpm_attest {

struct attestation_result {
    bool success;
    std::string ek_pub_pem;
    std::string ek_pub_hash;
    std::string ak_name_hex;
    std::string ak_pub_pem;
    std::string quote_signature_b64;
    std::string pcr_digest_b64;
    std::string pcr_values_hex;
    std::string attestation_json;
    std::string error;
};

struct quote_result {
    bool success;
    std::string quote_signature_b64;
    std::string pcr_digest_b64;
    std::string pcr_values_hex;
    std::string error;
};

bool tpm_available();

attestation_result generate_attestation(const std::string& nonce);

bool validate_attestation(const std::string& attestation_json,
                          const std::string& nonce,
                          const std::string& vendor_ak_pub_pem);

quote_result get_pcr_quote(const std::string& nonce);

std::string get_ek_public_pem();

std::string get_ek_hash();

std::string get_pcr_values(int pcr_count);

}