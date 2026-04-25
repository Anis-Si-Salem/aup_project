#include "license_embed.h"
#include "verifier.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

namespace license_embed {

static const char MAGIC_INSTALLED[] = "SECURELIC01";
static const char SENTINEL[] = "_LICDATA_REGION_4096_PLACEHOLDER__";

embedded_license g_license_region = []() {
    embedded_license e = {};
    memcpy(e.payload, SENTINEL, sizeof(SENTINEL) < sizeof(e.payload) ? sizeof(SENTINEL) : sizeof(e.payload));
    return e;
}();

static void compute_struct_integrity(const embedded_license& lic, uint8_t out[32]) {
    size_t len = offsetof(embedded_license, struct_integrity);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, &lic, len);
    EVP_DigestFinal_ex(ctx, out, nullptr);
    EVP_MD_CTX_free(ctx);
}

bool verify_embedded_integrity(const embedded_license& lic) {
    uint8_t expected[32];
    compute_struct_integrity(lic, expected);
    return memcmp(lic.struct_integrity, expected, 32) == 0;
}

bool verify_embedded_signature(const embedded_license& lic) {
    if (lic.canonical_json_len == 0 || lic.canonical_json_len >= sizeof(lic.payload)) return false;

    size_t json_len = lic.canonical_json_len;
    std::string canonical_json(lic.payload, json_len);
    std::string signature_raw(reinterpret_cast<const char*>(lic.ed25519_signature), 64);

    return verifier::verify_sig_only(canonical_json, signature_raw, "");
}

static bool read_from_binary(embedded_license& out) {
    char exe_path[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return false;
    exe_path[len] = '\0';

    std::ifstream f(exe_path, std::ios::binary);
    if (!f.is_open()) return false;

    std::string binary((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    f.close();

    for (size_t i = 0; i + sizeof(embedded_license) <= binary.size(); i++) {
        if (memcmp(binary.data() + i, MAGIC_INSTALLED, strlen(MAGIC_INSTALLED)) == 0) {
            embedded_license candidate;
            memcpy(&candidate, binary.data() + i, sizeof(embedded_license));

            if (!verify_embedded_integrity(candidate)) continue;

            out = candidate;
            return true;
        }
    }

    return false;
}

bool read_embedded(embedded_license& out) {
    if (read_from_binary(out)) return true;

    if (memcmp(g_license_region.magic, MAGIC_INSTALLED, strlen(MAGIC_INSTALLED)) != 0) {
        return false;
    }

    if (!verify_embedded_integrity(g_license_region)) return false;

    out = g_license_region;
    return true;
}

bool patch_binary(const std::string& src_path,
                  const std::string& dst_path,
                  const embedded_license& lic) {
    std::ifstream f(src_path, std::ios::binary);
    if (!f.is_open()) return false;

    std::string binary((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    f.close();

    size_t pos = binary.find(SENTINEL, 0);
    if (pos == std::string::npos) return false;

    size_t reserved_offset = offsetof(embedded_license, payload);
    if (pos < reserved_offset) return false;
    pos -= reserved_offset;

    if (pos + sizeof(embedded_license) > binary.size()) return false;

    embedded_license patched = lic;
    memcpy(patched.magic, MAGIC_INSTALLED, sizeof(MAGIC_INSTALLED));

    compute_struct_integrity(patched, patched.struct_integrity);

    memcpy(&binary[pos], &patched, sizeof(embedded_license));

    std::ofstream out(dst_path, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(binary.data(), binary.size());
    out.close();

    chmod(dst_path.c_str(), 0755);
    return true;
}

uint64_t get_expiry_timestamp() {
    embedded_license lic;
    if (!read_embedded(lic)) return 0;
    return lic.expiry_timestamp;
}

int get_days_remaining() {
    embedded_license lic;
    if (!read_embedded(lic)) return -1;
    time_t now = time(nullptr);
    double diff = difftime(static_cast<time_t>(lic.expiry_timestamp), now);
    return static_cast<int>(diff / 86400);
}

}