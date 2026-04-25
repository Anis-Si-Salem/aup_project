#include "secure_logger.h"
#include "tpm_attest.h"

#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <vector>
#include <algorithm>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

namespace secure_logger {

static constexpr uint8_t LOG_FILE_MAGIC[4] = {'A', 'U', 'D', 'T'};
static constexpr uint8_t LOG_VERSION = 2;  // Version 2 = chained entries
static constexpr uint16_t FP_FIELD_LEN = 64;

static const unsigned char VENDOR_RSA_PUBKEY_DER[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xab, 0x1d, 0x5d,
    0xa3, 0x6c, 0x86, 0xf1, 0xb1, 0x9f, 0xbe, 0x71, 0x48, 0x4f, 0xf9, 0xe7,
    0xe8, 0x29, 0x91, 0xb0, 0x4c, 0x01, 0x57, 0xa0, 0x51, 0x2a, 0xdb, 0xb3,
    0xca, 0xc4, 0x8f, 0x36, 0x78, 0xf0, 0x0f, 0x66, 0xbe, 0x73, 0x8b, 0x9c,
    0x6c, 0xd7, 0x66, 0x19, 0x7e, 0x30, 0x0a, 0x1f, 0x35, 0x63, 0xd6, 0x81,
    0x35, 0x7d, 0x1b, 0xd9, 0x54, 0xcc, 0xe0, 0xde, 0xab, 0x29, 0xc0, 0x31,
    0x28, 0x0d, 0x55, 0xf7, 0x70, 0x5f, 0xb8, 0x5d, 0x58, 0x6b, 0x3f, 0xf7,
    0xe6, 0x5a, 0xb7, 0x51, 0x63, 0xc9, 0x09, 0x74, 0xd5, 0x73, 0x76, 0x77,
    0x0f, 0xdf, 0xcc, 0x28, 0x30, 0x23, 0x44, 0xdb, 0xcb, 0xb6, 0xd8, 0xc1,
    0x4a, 0x69, 0x58, 0xb6, 0xb9, 0x6d, 0x3a, 0x0d, 0xf8, 0xd8, 0x39, 0x04,
    0xfa, 0xdf, 0x9a, 0xd2, 0x51, 0x3d, 0x9c, 0xf4, 0x21, 0x5c, 0x85, 0x4e,
    0x7c, 0x73, 0xee, 0x3d, 0x7a, 0x5b, 0xe8, 0xfd, 0x87, 0x58, 0x1f, 0x14,
    0x01, 0x3b, 0x8a, 0xc3, 0xb6, 0x55, 0xf1, 0xd6, 0x0c, 0x9c, 0xbc, 0x9f,
    0xf0, 0xc4, 0x37, 0x74, 0x81, 0x59, 0xba, 0x5c, 0x01, 0xae, 0x9c, 0x3b,
    0xec, 0xdf, 0x6d, 0xab, 0xc4, 0x38, 0xc8, 0xcb, 0x9b, 0x13, 0x8f, 0x80,
    0x5b, 0x2d, 0x62, 0x02, 0xb5, 0xe7, 0x31, 0x7a, 0xf4, 0x4b, 0x6e, 0xb5,
    0x0c, 0x1f, 0xc7, 0x2f, 0xd3, 0xf0, 0x1a, 0x73, 0x50, 0xdc, 0x84, 0x67,
    0x76, 0x37, 0xe7, 0xa9, 0x9c, 0x15, 0x58, 0x93, 0x1a, 0x62, 0x5b, 0x20,
    0x0f, 0xb6, 0xf7, 0xf5, 0x0b, 0x0d, 0x02, 0xdc, 0x12, 0xa1, 0xee, 0x07,
    0x73, 0xe9, 0x8d, 0xce, 0xf9, 0x01, 0x40, 0xe9, 0x63, 0xd8, 0x1b, 0x21,
    0xf8, 0x84, 0x15, 0xb8, 0xf4, 0xb1, 0x9d, 0xb1, 0xa2, 0x69, 0x0b, 0xf1,
    0x6c, 0x73, 0x5d, 0x5f, 0x57, 0x2b, 0xdc, 0x39, 0xfd, 0x5d, 0x0a, 0xa2,
    0xf7, 0x02, 0x03, 0x01, 0x00, 0x01
};
static const size_t VENDOR_RSA_PUBKEY_DER_LEN = sizeof(VENDOR_RSA_PUBKEY_DER);

static std::mutex g_mutex;
static std::vector<uint8_t> g_aes_key;
static std::vector<uint8_t> g_encrypted_aes_key;
static std::string g_log_path;
static std::string g_fingerprint;
static std::vector<uint8_t> g_chain_key;
static std::string g_last_chain_sig;
static uint32_t g_entry_count = 0;
static bool g_initialized = false;

static std::string ts() {
    char buf[32];
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    return buf;
}

static EVP_PKEY* load_vendor_rsa_pubkey() {
    const unsigned char* p = VENDOR_RSA_PUBKEY_DER;
    return d2i_PUBKEY(nullptr, &p, static_cast<long>(VENDOR_RSA_PUBKEY_DER_LEN));
}

static std::vector<uint8_t> rsa_encrypt_key(const uint8_t* key, size_t key_len) {
    EVP_PKEY* pkey = load_vendor_rsa_pubkey();
    if (!pkey) return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) { EVP_PKEY_free(pkey); return {}; }

    std::vector<uint8_t> result;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto done;

    {
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, key, key_len) <= 0) goto done;
        result.resize(outlen);
        if (EVP_PKEY_encrypt(ctx, result.data(), &outlen, key, key_len) <= 0) {
            result.clear();
            goto done;
        }
        result.resize(outlen);
    }

done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

static std::string compute_chain_signature(const std::string& prev_sig, 
                                           const std::string& entry_data) {
    if (g_chain_key.empty()) return "";
    
    // Chain signature: HMAC-SHA256(previous_signature + entry_data, chain_key)
    unsigned char hmac_out[32];
    std::string to_sign = prev_sig + entry_data;
    
    HMAC(EVP_sha256(), 
         g_chain_key.data(), g_chain_key.size(),
         reinterpret_cast<const unsigned char*>(to_sign.data()), to_sign.size(),
         hmac_out, nullptr);
    
    return std::string(reinterpret_cast<char*>(hmac_out), 32);
}

void init(const std::string& fingerprint_hex) {
    init(fingerprint_hex, "");
}

void init(const std::string& fingerprint_hex, const std::string& log_path_override) {
    std::lock_guard<std::mutex> lock(g_mutex);

    g_fingerprint = fingerprint_hex;
    if (g_fingerprint.size() > FP_FIELD_LEN)
        g_fingerprint = g_fingerprint.substr(0, FP_FIELD_LEN);

    uint8_t aes_key[32];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) return;
    g_aes_key.assign(aes_key, aes_key + 32);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));

    uint8_t chain_key[32];
    if (RAND_bytes(chain_key, sizeof(chain_key)) != 1) return;
    g_chain_key.assign(chain_key, chain_key + 32);
    OPENSSL_cleanse(chain_key, sizeof(chain_key));

    g_encrypted_aes_key = rsa_encrypt_key(g_aes_key.data(), g_aes_key.size());
    if (g_encrypted_aes_key.empty()) {
        g_aes_key.clear();
        g_chain_key.clear();
        return;
    }

    g_initialized = true;
    g_entry_count = 0;
    g_last_chain_sig = std::string(32, '\0');

    if (!log_path_override.empty()) {
        g_log_path = log_path_override;
    } else {
        const char* env_path = getenv("AUDIT_LOG_PATH");
        if (env_path && env_path[0] != '\0') {
            g_log_path = env_path;
        } else {
            char exe[4096] = {};
            ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
            if (len > 0) {
                exe[len] = '\0';
                std::string dir(exe);
                auto slash = dir.rfind('/');
                if (slash != std::string::npos) {
                    g_log_path = dir.substr(0, slash + 1) + "app_audit.enc";
                } else {
                    g_log_path = "app_audit.enc";
                }
            } else {
                g_log_path = "app_audit.enc";
            }
        }
    }

    std::ifstream test(g_log_path, std::ios::binary);
    if (!test.is_open()) {
        std::ofstream of(g_log_path, std::ios::binary);
        uint8_t version = LOG_VERSION;
        uint16_t enc_key_len = static_cast<uint16_t>(g_encrypted_aes_key.size());

        of.write(reinterpret_cast<const char*>(LOG_FILE_MAGIC), 4);
        of.write(reinterpret_cast<const char*>(&version), 1);

        uint8_t fp_len = static_cast<uint8_t>(g_fingerprint.size());
        of.write(reinterpret_cast<const char*>(&fp_len), 1);
        of.write(g_fingerprint.c_str(), g_fingerprint.size());

        of.write(reinterpret_cast<const char*>(&enc_key_len), 2);
        of.write(reinterpret_cast<const char*>(g_encrypted_aes_key.data()), enc_key_len);
        
        std::vector<uint8_t> encrypted_chain = rsa_encrypt_key(g_chain_key.data(), g_chain_key.size());
        uint16_t chain_key_len = static_cast<uint16_t>(encrypted_chain.size());
        of.write(reinterpret_cast<const char*>(&chain_key_len), 2);
        of.write(reinterpret_cast<const char*>(encrypted_chain.data()), chain_key_len);
    }
}

static bool encrypt_append(const std::string& plaintext) {
    if (g_aes_key.size() != 32) return false;

    // Get current fingerprint for this log entry
    // Fingerprint = TPM EK hash (already bound to license in vendor DB)
    std::string current_fingerprint = g_fingerprint;
    if (current_fingerprint.empty()) {
        current_fingerprint = "UNKNOWN";
    }

    std::string entry_data = ts() + " | FP:" + current_fingerprint + " | " + plaintext;
    
    std::string prev_sig = g_last_chain_sig;
    if (g_entry_count == 0) {
        prev_sig = std::string(entry_data.substr(0, std::min(entry_data.size(), (size_t)32)));
    }
    
    std::string chain_sig = compute_chain_signature(prev_sig, entry_data);
    g_last_chain_sig = chain_sig;
    
    // Final entry includes chain signature
    std::string final_entry = entry_data + " | CHAIN:" + chain_sig;
    
    g_entry_count++;

    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<uint8_t> ciphertext(final_entry.size() + 16);
    int len = 0, ct_len = 0;
    bool ok = false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, g_aes_key.data(), iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(final_entry.data()),
                          static_cast<int>(final_entry.size())) != 1) goto done;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) goto done;
    ct_len += len;
    {
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;

        std::ofstream f(g_log_path, std::ios::binary | std::ios::app);
        if (!f.is_open()) goto done;

        uint32_t total = static_cast<uint32_t>(12 + ct_len + 16);
        f.write(reinterpret_cast<const char*>(&total), 4);
        f.write(reinterpret_cast<const char*>(iv), 12);
        f.write(reinterpret_cast<const char*>(ciphertext.data()), ct_len);
        f.write(reinterpret_cast<const char*>(tag), 16);
        ok = true;
    }

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void log(const std::string& event, const std::string& detail) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized) return;

    std::string entry = event;
    if (!detail.empty()) entry += " | " + detail;

    encrypt_append(entry);
}

void log_startup() { log("STARTUP", "Application launched"); }
void log_hw_validation(const std::string& fp_hash, bool match) {
    log("HW_VALIDATION", std::string(match ? "MATCH" : "MISMATCH") + " fp=" + fp_hash);
}
void log_tamper(const std::string& reason) { log("TAMPER_DETECTED", reason); }
void log_tpm(const std::string& event, bool success) {
    log("TPM", event + (success ? " OK" : " FAIL"));
}
void log_license(const std::string& action, bool success) {
    log("LICENSE", action + (success ? " OK" : " FAIL"));
}
void log_seal(const std::string& action, bool success) {
    log("SEAL", action + (success ? " OK" : " FAIL"));
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) {
        OPENSSL_cleanse(g_aes_key.data(), g_aes_key.size());
        g_aes_key.clear();
        OPENSSL_cleanse(g_chain_key.data(), g_chain_key.size());
        g_chain_key.clear();
        g_encrypted_aes_key.clear();
        g_initialized = false;
    }
}

}