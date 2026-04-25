#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace app_loader {

bool decrypt_payload(const std::vector<uint8_t>& ciphertext,
                      const uint8_t key[32],
                      std::vector<uint8_t>& plaintext);

int load_and_run(const std::string& encrypted_path);

bool re_encrypt_payload(const std::string& vendor_enc_path,
                        const uint8_t vendor_key[32],
                        uint8_t new_key[32],
                        const std::string& output_path);

}