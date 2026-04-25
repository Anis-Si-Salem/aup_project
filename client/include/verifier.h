#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace verifier {

struct license_data {
    std::string fingerprint;
    std::string issued_at;
    std::string expires_at;
    int max_users;
    std::string signature_b64;
    uint64_t expiry_timestamp;
};

bool verify_license(const std::string& json_str,
                    const std::string& pubkey_pem,
                    license_data& out);

bool verify_sig_only(const std::string& canonical_json,
                     const std::string& signature_raw,
                     const std::string& pubkey_pem);

std::string extract_signature(const std::string& json_str);
std::string strip_signature(const std::string& json_str);

std::vector<uint8_t> b64_decode_raw(const std::string& in);

bool check_expiry(const license_data& lic);
int days_remaining(const license_data& lic);
bool is_expired(const license_data& lic);

std::string get_embedded_pubkey();

}