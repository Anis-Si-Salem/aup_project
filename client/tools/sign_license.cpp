#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

static std::string b64_encode(const uint8_t* data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(4 * ((len + 2) / 3));
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out += tbl[(n >> 18) & 0x3f];
        out += tbl[(n >> 12) & 0x3f];
        out += (i + 1 < len) ? tbl[(n >> 6) & 0x3f] : '=';
        out += (i + 2 < len) ? tbl[n & 0x3f] : '=';
    }
    return out;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <license.json> <private_key.pem>\n";
        std::cerr << "  Reads license.json, signs it, and writes signature back into license.json\n";
        return 1;
    }

    std::ifstream lf(argv[1]);
    if (!lf.is_open()) {
        std::cerr << "Cannot open " << argv[1] << "\n";
        return 1;
    }
    std::string json_str((std::istreambuf_iterator<char>(lf)),
                          std::istreambuf_iterator<char>());

    nlohmann::json j = nlohmann::json::parse(json_str);
    j.erase("signature");
    std::string canonical = j.dump(-1, ' ', true);

    BIO* bio = BIO_new_file(argv[2], "r");
    if (!bio) {
        std::cerr << "Cannot open " << argv[2] << "\n";
        return 1;
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        std::cerr << "Failed to read private key\n";
        return 1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return 1; }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
        std::cerr << "DigestSignInit failed\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(canonical.data()),
                       canonical.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(ctx, sig.data(), &sig_len,
                       reinterpret_cast<const unsigned char*>(canonical.data()),
                       canonical.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    std::string sig_b64 = b64_encode(sig.data(), sig_len);

    // Write signature back into JSON
    j["signature"] = sig_b64;
    std::string output = j.dump(2);

    std::ofstream of(argv[1]);
    of << output << "\n";
    of.close();

    std::cout << "Signed license written to " << argv[1] << "\n";
    std::cout << "Signature (base64, " << sig_len << " bytes): " << sig_b64.substr(0, 40) << "...\n";

    return 0;
}