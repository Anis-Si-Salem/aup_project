#include "app_loader.h"
#include "anti_re.h"
#include "license_embed.h"
#include "secure_logger.h"
#include "tpm_seal.h"
#include "tpm_attest.h"

#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x40
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x20
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x10
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x08
#endif

namespace app_loader {

static bool read_file_bytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    f.seekg(0, std::ios::end);
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(sz);
    f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good();
}

static bool write_file_bytes(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

bool decrypt_payload(const std::vector<uint8_t>& ciphertext,
                     const uint8_t key[32],
                     std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() < 12 + 16) return false;

    const uint8_t* iv = ciphertext.data();
    const uint8_t* tag = ciphertext.data() + ciphertext.size() - 16;
    size_t ct_len = ciphertext.size() - 12 - 16;
    const uint8_t* ct = ciphertext.data() + 12;

    plaintext.resize(ct_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        goto cleanup;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
        goto cleanup;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct, static_cast<int>(ct_len)) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1)
        goto cleanup;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1) {
        ok = true;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool encrypt_payload(const std::vector<uint8_t>& plaintext,
                             const uint8_t key[32],
                             std::vector<uint8_t>& ciphertext) {
    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<uint8_t> ct(plaintext.size() + 16);
    int len = 0, ct_len = 0;
    bool ok = false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) goto done;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &len) != 1) goto done;
    ct_len += len;
    {
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
        ciphertext.resize(12 + ct_len + 16);
        memcpy(ciphertext.data(), iv, 12);
        memcpy(ciphertext.data() + 12, ct.data(), ct_len);
        memcpy(ciphertext.data() + 12 + ct_len, tag, 16);
        ok = true;
    }

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool re_encrypt_payload(const std::string& vendor_enc_path,
                        const uint8_t vendor_key[32],
                        uint8_t new_key[32],
                        const std::string& output_path) {
    if (RAND_bytes(new_key, 32) != 1) return false;

    std::vector<uint8_t> ciphertext;
    if (!read_file_bytes(vendor_enc_path, ciphertext)) return false;

    std::vector<uint8_t> plaintext;
    if (!decrypt_payload(ciphertext, vendor_key, plaintext)) return false;

    std::vector<uint8_t> new_ciphertext;
    if (!encrypt_payload(plaintext, new_key, new_ciphertext)) return false;

    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    if (!write_file_bytes(output_path, new_ciphertext)) return false;

    return true;
}

static int memfd_load(const uint8_t* data, size_t size) {
    int fd = memfd_create("ld-linux-x86-64.so.2", MFD_CLOEXEC);
    if (fd < 0) return -1;

    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) != 0) {
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    std::string path = "/proc/self/fd/" + std::to_string(fd);
    void* handle = dlopen(path.c_str(), RTLD_NOW);

    close(fd);

    if (!handle) {
        std::cerr << "      dlopen failed: " << dlerror() << std::endl;
        return -1;
    }

    using app_main_t = int(*)();
    app_main_t entry = reinterpret_cast<app_main_t>(dlsym(handle, "app_main"));
    if (!entry) {
        std::cerr << "      dlsym failed: " << dlerror() << std::endl;
        dlclose(handle);
        return -1;
    }

    unsetenv("LD_PRELOAD");
    unsetenv("DYLD_INSERT_LIBRARIES");

    int rc = entry();
    dlclose(handle);
    return rc;
}

static bool tpm_unseal_key(const std::string& tss_path, uint8_t key[32]) {
    if (!tpm_attest::tpm_available()) {
        secure_logger::log_tpm("unseal_key", false);
        return false;
    }

    std::vector<uint8_t> sealed_blob;
    if (!read_file_bytes(tss_path, sealed_blob)) {
        secure_logger::log_seal("read_sealed_key", false);
        return false;
    }

    auto result = tpm_seal::unseal_license_key(sealed_blob);
    if (!result.success || result.data.size() != 32) {
        secure_logger::log_seal("unseal_key", false);
        return false;
    }

    memcpy(key, result.data.data(), 32);
    OPENSSL_cleanse(result.data.data(), result.data.size());
    secure_logger::log_seal("unseal_key", true);
    return true;
}

int load_and_run(const std::string& encrypted_path) {
    if (anti_re::check_tracer_pid()) {
        secure_logger::log_tamper("tracer_detected_on_load");
        return -1;
    }

    // Verify TPM is present and matches license
    if (!tpm_attest::tpm_available()) {
        secure_logger::log_tpm("no_tpm_on_runtime", false);
        std::cerr << "  ERROR: TPM disappeared or unavailable.\n";
        return -1;
    }

    std::string current_ek_hash = tpm_attest::get_ek_hash();

    license_embed::embedded_license emb;
    if (license_embed::read_embedded(emb)) {
        if (!license_embed::verify_embedded_integrity(emb)) {
            secure_logger::log_tamper("embedded_integrity_fail");
            return -1;
        }
        if (!license_embed::verify_embedded_signature(emb)) {
            secure_logger::log_tamper("embedded_sig_fail");
            return -1;
        }

        // Verify TPM EK hash matches embedded
        // The embedded license contains the TPM EK hash in fp_hash field
        // Extract it from the embedded struct and verify
        if (strlen(emb.fp_hash) > 0 && !current_ek_hash.empty()) {
            std::string embedded_tpm_hash(emb.fp_hash, strlen(emb.fp_hash));
            // Check if embedded hash is the TPM hash (not a generic fingerprint)
            if (embedded_tpm_hash.find(current_ek_hash) == std::string::npos &&
                current_ek_hash.find(embedded_tpm_hash) == std::string::npos) {
                // TPM mismatch - could be license was for different TPM
                secure_logger::log_tpm("tpm_hash_mismatch", false);
                std::cerr << "  ERROR: TPM hardware mismatch detected.\n";
                std::cerr << "  The license was issued for a different TPM.\n";
                return -1;
            }
        }

        if (emb.expiry_timestamp > 0) {
            time_t now = time(nullptr);
            if (static_cast<time_t>(emb.expiry_timestamp) < now) {
                secure_logger::log_license("expired", false);
                return -1;
            }
        }
    } else {
        secure_logger::log_license("no_embedded", false);
        return -1;
    }

    std::string payload_path = encrypted_path;
    {
        char exe[4096] = {};
        ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (len > 0) {
            exe[len] = '\0';
            std::string exe_dir(exe);
            auto slash = exe_dir.rfind('/');
            if (slash != std::string::npos) {
                std::string candidate = exe_dir.substr(0, slash + 1) + encrypted_path;
                std::ifstream test(candidate, std::ios::binary);
                if (test.is_open()) payload_path = candidate;
            }
        }
    }

    uint8_t aes_key[32];
    std::string tss_path = payload_path + ".key.tss";
    std::string fallback_path = payload_path + ".key.bin";
    bool key_ok = false;

    if (tpm_attest::tpm_available()) {
        key_ok = tpm_unseal_key(tss_path, aes_key);
        if (!key_ok) {
            std::cerr << "      TPM unseal failed - trying fallback key.\n";
            secure_logger::log_seal("tpm_unseal_failed_trying_fallback", false);
        }
    }

    if (!key_ok) {
        std::vector<uint8_t> fallback_data;
        if (read_file_bytes(fallback_path, fallback_data) && fallback_data.size() == 32) {
            memcpy(aes_key, fallback_data.data(), 32);
            OPENSSL_cleanse(fallback_data.data(), fallback_data.size());
            key_ok = true;
            secure_logger::log_seal("fallback_key_loaded", true);
        } else {
            std::cerr << "      No decryption key available (TPM and fallback both failed).\n";
            secure_logger::log_seal("no_key_available", false);
            _exit(137);
        }
    }

    std::vector<uint8_t> ciphertext;
    if (!read_file_bytes(payload_path, ciphertext)) {
        std::cerr << "      Cannot open " << payload_path << "\n";
        return -1;
    }

    std::vector<uint8_t> plaintext;
    if (decrypt_payload(ciphertext, aes_key, plaintext)) {
        std::cout << "      Decrypted payload (" << plaintext.size() << " bytes)\n";
        mlock(plaintext.data(), plaintext.size());
        int rc = memfd_load(plaintext.data(), plaintext.size());
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        munlock(plaintext.data(), plaintext.size());
        return rc < 0 ? 1 : rc;
    }

    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    secure_logger::log_seal("decrypt_failed", false);
    std::cerr << "      Decryption of " << encrypted_path << " failed.\n";
    return -1;
}

}