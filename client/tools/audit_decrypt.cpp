#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>

static std::vector<uint8_t> rsa_decrypt_key(EVP_PKEY* pkey,
                                             const std::vector<uint8_t>& encrypted_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) return {};

    std::vector<uint8_t> result;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto done;

    {
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                             encrypted_key.data(), encrypted_key.size()) <= 0) goto done;
        result.resize(outlen);
        if (EVP_PKEY_decrypt(ctx, result.data(), &outlen,
                             encrypted_key.data(), encrypted_key.size()) <= 0) {
            result.clear();
            goto done;
        }
        result.resize(outlen);
    }

done:
    EVP_PKEY_CTX_free(ctx);
    return result;
}

static bool decrypt_entry(const std::vector<uint8_t>& data, size_t offset,
                          const uint8_t aes_key[32],
                          std::string& plaintext) {
    if (offset + 4 > data.size()) return false;

    uint32_t total;
    memcpy(&total, data.data() + offset, 4);
    if (total < 12 + 16 || offset + 4 + total > data.size()) return false;

    const uint8_t* iv = data.data() + offset + 4;
    const uint8_t* ct = data.data() + offset + 4 + 12;
    size_t ct_len = total - 12 - 16;
    const uint8_t* tag = data.data() + offset + 4 + total - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    bool ok = false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, static_cast<int>(ct_len)) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt.data() + len, &len) == 1) {
        plaintext = std::string(pt.begin(), pt.end());
        ok = true;
    }

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <app_audit.enc> <vendor_private_key.pem>\n\n"
                  << "  Decrypts the encrypted audit log using the vendor's RSA private key.\n"
                  << "  The log file was encrypted with the vendor's RSA public key during\n"
                  << "  client operation. Only the vendor's private key can decrypt it.\n\n"
                  << "  The fingerprint and encrypted AES key are embedded in the file header.\n";
        return 1;
    }

    std::string log_path = argv[1];
    std::string privkey_path = argv[2];

    BIO* bio = BIO_new_file(privkey_path.c_str(), "r");
    if (!bio) {
        std::cerr << "Error: Cannot open private key: " << privkey_path << "\n";
        return 1;
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        std::cerr << "Error: Failed to parse private key.\n";
        return 1;
    }

    std::ifstream f(log_path, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Error: Cannot open " << log_path << "\n";
        EVP_PKEY_free(pkey);
        return 1;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    f.close();

    if (data.size() < 16 || data[0] != 'A' || data[1] != 'U' ||
        data[2] != 'D' || data[3] != 'T') {
        std::cerr << "Error: Not a valid audit log file (bad magic).\n";
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (data[4] != 1 && data[4] != 2) {
        std::cerr << "Error: Unsupported log version: " << (int)data[4] << " (expected 1 or 2)\n";
        EVP_PKEY_free(pkey);
        return 1;
    }
    int log_version = data[4];
    if (log_version == 2) {
        std::cout << "  [Log version 2: chained HMAC entries]\n";
    }

    size_t offset = 5;
    uint8_t fp_len = data[offset++];
    std::string fingerprint(data.begin() + offset, data.begin() + offset + fp_len);
    offset += fp_len;

    uint16_t enc_key_len;
    memcpy(&enc_key_len, data.data() + offset, 2);
    offset += 2;

    if (offset + enc_key_len > data.size()) {
        std::cerr << "Error: File truncated (encrypted key).\n";
        EVP_PKEY_free(pkey);
        return 1;
    }

    std::vector<uint8_t> encrypted_aes_key(data.begin() + offset,
                                             data.begin() + offset + enc_key_len);
    offset += enc_key_len;

    if (log_version == 2) {
        if (offset + 2 > data.size()) {
            std::cerr << "Error: File truncated (chain key length).\n";
            EVP_PKEY_free(pkey);
            return 1;
        }
        uint16_t chain_key_len;
        memcpy(&chain_key_len, data.data() + offset, 2);
        offset += 2;
        if (offset + chain_key_len > data.size()) {
            std::cerr << "Error: File truncated (chain key data).\n";
            EVP_PKEY_free(pkey);
            return 1;
        }
        std::vector<uint8_t> encrypted_chain_key(data.begin() + offset,
                                                  data.begin() + offset + chain_key_len);
        offset += chain_key_len;

        std::vector<uint8_t> chain_key = rsa_decrypt_key(pkey, encrypted_chain_key);
        if (chain_key.size() == 32) {
            std::cout << "  [Chain key decrypted successfully (" << chain_key.size() << " bytes)]\n";
        } else {
            std::cout << "  [Chain key decryption failed]\n";
        }
    }

    std::cout << "=== Encrypted Audit Log: " << log_path << " ===\n";
    std::cout << "  Client Fingerprint: " << fingerprint << "\n\n";

    std::vector<uint8_t> aes_key = rsa_decrypt_key(pkey, encrypted_aes_key);
    EVP_PKEY_free(pkey);

    if (aes_key.size() != 32) {
        std::cerr << "Error: RSA decryption failed (wrong private key?).\n";
        return 1;
    }

    int count = 0;
    while (offset + 4 <= data.size()) {
        std::string plaintext;
        if (!decrypt_entry(data, offset, aes_key.data(), plaintext)) {
            std::cerr << "  [DECRYPT FAILED at offset " << offset << "]\n";
            break;
        }
        std::cout << "  " << plaintext << "\n";
        count++;

        uint32_t total;
        memcpy(&total, data.data() + offset, 4);
        offset += 4 + total;
    }

    std::cout << "\n=== " << count << " entries decrypted ===\n";
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    return 0;
}