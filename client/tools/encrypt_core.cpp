#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <input.so> <output.enc> [keyfile.key]\n";
    std::cerr << "  If keyfile is provided, reads 32-byte AES key from it.\n";
    std::cerr << "  Otherwise, generates a random key and writes it to <output.enc>.key\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    uint8_t key[32];
    bool key_from_file = false;

    if (argc == 4) {
        std::ifstream kf(argv[3], std::ios::binary);
        if (!kf.is_open()) {
            std::cerr << "Cannot open key file: " << argv[3] << "\n";
            return 1;
        }
        if (!kf.read(reinterpret_cast<char*>(key), 32)) {
            std::cerr << "Key file must be exactly 32 bytes.\n";
            return 1;
        }
        key_from_file = true;
    } else {
        if (RAND_bytes(key, sizeof(key)) != 1) {
            std::cerr << "Failed to generate random key.\n";
            return 1;
        }
    }

    std::ifstream inf(argv[1], std::ios::binary);
    if (!inf.is_open()) {
        std::cerr << "Cannot open " << argv[1] << "\n";
        return 1;
    }
    inf.seekg(0, std::ios::end);
    size_t size = inf.tellg();
    inf.seekg(0, std::ios::beg);

    std::vector<uint8_t> plaintext(size);
    inf.read(reinterpret_cast<char*>(plaintext.data()), size);
    inf.close();

    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cerr << "Failed to generate IV.\n";
        return 1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "EVP_CIPHER_CTX_new failed\n"; return 1; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "EncryptInit failed\n"; return 1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        std::cerr << "SetIVLen failed\n"; return 1;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        std::cerr << "SetKey/IV failed\n"; return 1;
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        std::cerr << "EncryptUpdate failed\n"; return 1;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "EncryptFinal failed\n"; return 1;
    }
    ciphertext_len += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        std::cerr << "GetTag failed\n"; return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    std::ofstream of(argv[2], std::ios::binary);
    of.write(reinterpret_cast<const char*>(iv), 12);
    of.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
    of.write(reinterpret_cast<const char*>(tag), 16);
    of.close();

    std::cout << "Encrypted " << plaintext.size() << " bytes -> " << argv[2] << "\n";
    std::cout << "Output size: " << (12 + ciphertext_len + 16) << " bytes\n";

    if (!key_from_file) {
        std::string keyfile = std::string(argv[2]) + ".key";
        std::ofstream kf(keyfile, std::ios::binary);
        if (kf.is_open()) {
            kf.write(reinterpret_cast<const char*>(key), 32);
            kf.close();
            std::cout << "Key written to " << keyfile << "\n";
            std::cout << "Distribute this key file alongside the encrypted payload.\n";
        } else {
            std::cerr << "WARNING: Could not write key file to " << keyfile << "\n";
        }
    }

    OPENSSL_cleanse(key, sizeof(key));
    return 0;
}