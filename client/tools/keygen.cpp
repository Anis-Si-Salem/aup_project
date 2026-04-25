#include <cstring>
#include <fstream>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <output_privkey.pem> <output_pubkey.pem>\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
    if (!ctx) {
        std::cerr << "Failed to create ED25519 context\n";
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Failed to init keygen\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Failed to generate key\n";
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    // Write private key
    {
        BIO* bio = BIO_new_file(argv[1], "w");
        if (!bio) {
            std::cerr << "Cannot open " << argv[1] << " for writing\n";
            EVP_PKEY_free(pkey);
            return 1;
        }
        PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(bio);
        std::cout << "Private key written to " << argv[1] << "\n";
    }

    // Write public key
    {
        BIO* bio = BIO_new_file(argv[2], "w");
        if (!bio) {
            std::cerr << "Cannot open " << argv[2] << " for writing\n";
            EVP_PKEY_free(pkey);
            return 1;
        }
        PEM_write_bio_PUBKEY(bio, pkey);
        BIO_free(bio);
        std::cout << "Public key written to " << argv[2] << "\n";
    }

    // Also print the public key PEM for embedding in installer
    {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, pkey);
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::cout << "\n--- Public key for embedding in installer ---\n";
        std::cout << std::string(data, len) << "\n";
        BIO_free(bio);
    }

    EVP_PKEY_free(pkey);
    return 0;
}