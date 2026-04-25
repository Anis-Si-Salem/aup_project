#include "verifier.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ctime>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static const unsigned char EMBEDDED_PUBKEY_DER[] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
    0x21, 0x00, 0xdf, 0x6c, 0xf0, 0xe4, 0x6e, 0x6a, 0x41, 0x3e,
    0x91, 0x68, 0x5e, 0xc0, 0xde, 0x70, 0xd4, 0xbb, 0x4f, 0x65,
    0xaf, 0x3e, 0x57, 0x07, 0x96, 0xde, 0xdc, 0xbd, 0xcb, 0x83,
    0x47, 0x29, 0x93, 0x95
};
static const size_t EMBEDDED_PUBKEY_DER_LEN = sizeof(EMBEDDED_PUBKEY_DER);

namespace verifier {

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

static std::vector<uint8_t> b64_decode(const std::string& in) {
    static int8_t dt[256];
    static bool init = false;
    if (!init) {
        memset(dt, -1, sizeof(dt));
        for (int i = 0; i < 26; i++) dt[static_cast<unsigned char>('A'+i)] = i;
        for (int i = 0; i < 26; i++) dt[static_cast<unsigned char>('a'+i)] = 26+i;
        for (int i = 0; i < 10; i++) dt[static_cast<unsigned char>('0'+i)] = 52+i;
        dt[static_cast<unsigned char>('+')] = 62;
        dt[static_cast<unsigned char>('/')] = 63;
        init = true;
    }
    std::vector<uint8_t> out;
    out.reserve(in.size() * 3 / 4);
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') break;
        if (dt[c] == -1) break;
        val = (val << 6) + dt[c];
        valb += 6;
        if (valb >= 0) { out.push_back(static_cast<uint8_t>((val >> valb) & 0xff)); valb -= 8; }
    }
    return out;
}

std::vector<uint8_t> b64_decode_raw(const std::string& in) {
    return b64_decode(in);
}

static std::string pem_from_der(const unsigned char* der, size_t len) {
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    std::string b64 = b64_encode(der, len);
    for (size_t i = 0; i < b64.size(); i += 64) {
        pem += b64.substr(i, 64);
        pem += '\n';
    }
    pem += "-----END PUBLIC KEY-----\n";
    return pem;
}

std::string extract_signature(const std::string& json_str) {
    try {
        auto j = nlohmann::json::parse(json_str);
        return j.value("signature", "");
    } catch (...) { return ""; }
}

std::string strip_signature(const std::string& json_str) {
    try {
        auto j = nlohmann::json::parse(json_str);
        j.erase("signature");
        return j.dump(-1, ' ', true);
    } catch (...) { return json_str; }
}

bool verify_sig_only(const std::string& canonical_json,
                     const std::string& signature_raw,
                     const std::string& pubkey_pem) {
    std::string key = pubkey_pem;
    if (key.empty() || key.find("-----BEGIN") == std::string::npos) {
        key = get_embedded_pubkey();
    }

    BIO* bio = BIO_new_mem_buf(key.data(), static_cast<int>(key.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }

    bool result = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int rc = EVP_DigestVerify(ctx,
            reinterpret_cast<const unsigned char*>(signature_raw.data()),
            signature_raw.size(),
            reinterpret_cast<const unsigned char*>(canonical_json.data()),
            canonical_json.size());
        result = (rc == 1);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

bool verify_license(const std::string& json_str,
                    const std::string& pubkey_pem,
                    license_data& out) {
    std::string sig_b64 = extract_signature(json_str);
    if (sig_b64.empty()) return false;

    auto sig_bytes = b64_decode(sig_b64);
    std::string canonical = strip_signature(json_str);

    if (!verify_sig_only(canonical,
                         std::string(sig_bytes.begin(), sig_bytes.end()),
                         pubkey_pem)) {
        return false;
    }

    try {
        auto j = nlohmann::json::parse(json_str);
        out.fingerprint = j.value("fingerprint", "");
        out.issued_at = j.value("issued_at", "");
        out.expires_at = j.value("expires_at", "");
        out.max_users = j.value("max_users", 0);
        out.signature_b64 = sig_b64;

        struct tm tm_exp = {};
        if (strptime(out.expires_at.c_str(), "%Y-%m-%dT%H:%M:%S", &tm_exp)) {
            out.expiry_timestamp = static_cast<uint64_t>(timegm(&tm_exp));
        }
        return !out.fingerprint.empty() && !out.expires_at.empty();
    } catch (...) { return false; }
}

bool check_expiry(const license_data& lic) {
    return lic.expiry_timestamp > static_cast<uint64_t>(time(nullptr));
}

int days_remaining(const license_data& lic) {
    time_t now = time(nullptr);
    double diff = difftime(static_cast<time_t>(lic.expiry_timestamp), now);
    return static_cast<int>(diff / 86400);
}

bool is_expired(const license_data& lic) {
    return !check_expiry(lic);
}

std::string get_embedded_pubkey() {
    return pem_from_der(EMBEDDED_PUBKEY_DER, EMBEDDED_PUBKEY_DER_LEN);
}

}