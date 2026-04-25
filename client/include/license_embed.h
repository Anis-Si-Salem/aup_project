#pragma once

#include <string>
#include <cstdint>

namespace license_embed {

#pragma pack(push, 1)
struct embedded_license {
    char magic[16];
    uint32_t version;
    uint64_t expiry_timestamp;
    char fp_hash[65];
    uint8_t ed25519_signature[64];
    uint16_t canonical_json_len;
    uint8_t struct_integrity[32];
    char payload[3905];
};
#pragma pack(pop)

static_assert(sizeof(embedded_license) == 4096, "embedded_license must be 4096 bytes");

extern embedded_license g_license_region;

bool patch_binary(const std::string& src_path,
                  const std::string& dst_path,
                  const embedded_license& lic);

bool read_embedded(embedded_license& out);

bool verify_embedded_integrity(const embedded_license& lic);

bool verify_embedded_signature(const embedded_license& lic);

uint64_t get_expiry_timestamp();
int get_days_remaining();

}