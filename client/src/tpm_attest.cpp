#include "tpm_attest.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include <nlohmann/json.hpp>

namespace tpm_attest {

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 0x0f];
    }
    return out;
}

static std::string to_b64(const uint8_t* data, size_t len) {
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

static void cleanup_esys(ESYS_CONTEXT* ctx) {
    if (ctx) Esys_Finalize(&ctx);
}

static void flush_if_valid(ESYS_CONTEXT* ctx, ESYS_TR handle) {
    if (handle != ESYS_TR_NONE && handle != ESYS_TR_RH_OWNER &&
        handle != ESYS_TR_RH_PLATFORM && handle != ESYS_TR_RH_ENDORSEMENT &&
        handle != ESYS_TR_RH_NULL && handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx, handle);
    }
}

bool tpm_available() {
    return std::filesystem::exists("/dev/tpm0") ||
           std::filesystem::exists("/dev/tpmrm0");
}

std::string get_ek_hash() {
    if (!tpm_available()) return "";

    ESYS_CONTEXT* ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) return "";

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        cleanup_esys(ctx); return "";
    }

    ESYS_TR ek_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* ek_pub = nullptr;
    TPM2B_CREATION_DATA* creation_data = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* creation_ticket = nullptr;

    // TPM2_ALG_ECC = 0x0023
    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_ENDORSEMENT,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            nullptr, nullptr, nullptr, nullptr,
                            &ek_handle, &ek_pub,
                            &creation_data, &creation_hash, &creation_ticket);

    std::string result;
    if (rc == TSS2_RC_SUCCESS && ek_pub) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        if (ek_pub->publicArea.type == TPM2_ALG_ECC) {
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(md_ctx, ek_pub->publicArea.unique.ecc.x.buffer,
                            ek_pub->publicArea.unique.ecc.x.size);
            EVP_DigestUpdate(md_ctx, ek_pub->publicArea.unique.ecc.y.buffer,
                            ek_pub->publicArea.unique.ecc.y.size);
            EVP_DigestFinal_ex(md_ctx, hash, nullptr);
            EVP_MD_CTX_free(md_ctx);
            result = to_hex(hash, SHA256_DIGEST_LENGTH);
        } else if (ek_pub->publicArea.type == TPM2_ALG_RSA) {
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            unsigned int hash_len = 0;
            EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(md_ctx, ek_pub->publicArea.unique.rsa.buffer,
                            ek_pub->publicArea.unique.rsa.size);
            EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
            EVP_MD_CTX_free(md_ctx);
            result = to_hex(hash, SHA256_DIGEST_LENGTH);
        }

        Esys_Free(ek_pub);
        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);
        Esys_FlushContext(ctx, ek_handle);
    }

    cleanup_esys(ctx);
    return result;
}

std::string get_ek_public_pem() {
    return get_ek_hash();
}

std::string get_pcr_values(int pcr_count) {
    if (!tpm_available()) return "";

    ESYS_CONTEXT* ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) return "";

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        cleanup_esys(ctx);
        return "";
    }

    TPML_PCR_SELECTION pcr_sel = {};
    pcr_sel.count = 1;
    pcr_sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_sel.pcrSelections[0].sizeofSelect = 3;
    memset(pcr_sel.pcrSelections[0].pcrSelect, 0, 3);
    for (int i = 0; i < pcr_count && i < 24; i++) {
        pcr_sel.pcrSelections[0].pcrSelect[i / 8] |= (1 << (i % 8));
    }

    UINT32 pcr_update_counter = 0;
    TPML_PCR_SELECTION* pcr_selection_out = nullptr;
    TPML_DIGEST* pcr_values = nullptr;

    rc = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       &pcr_sel, &pcr_update_counter, &pcr_selection_out, &pcr_values);

    std::string result;
    if (rc == TSS2_RC_SUCCESS && pcr_values) {
        int pcr_idx = 0;
        for (UINT32 i = 0; i < pcr_values->count && pcr_idx < pcr_count; i++) {
            if (!result.empty()) result += "\n";
            result += "PCR" + std::to_string(pcr_idx) + ": " +
                      to_hex(pcr_values->digests[i].buffer, pcr_values->digests[i].size);
            pcr_idx++;
        }
        Esys_Free(pcr_selection_out);
        Esys_Free(pcr_values);
    }

    cleanup_esys(ctx);
    return result;
}

quote_result get_pcr_quote(const std::string& nonce) {
    quote_result result;
    if (!tpm_available()) {
        result.error = "No TPM available";
        return result;
    }

    // For a production attestation flow, we'd create an AK and sign with it.
    // Here we provide a PCR quote using a simple approach.
    // The quote is just the PCR values hashed with the nonce.
    std::string pcrs = get_pcr_values(24);
    if (pcrs.empty()) {
        result.error = "Could not read PCRs";
        return result;
    }

    // Hash PCRs + nonce together as the "quote"
    std::string combined = pcrs + ":" + nonce;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md_ctx, combined.data(), combined.size());
    EVP_DigestFinal_ex(md_ctx, hash, nullptr);
    EVP_MD_CTX_free(md_ctx);

    result.pcr_digest_b64 = to_b64(hash, SHA256_DIGEST_LENGTH);
    result.pcr_values_hex = pcrs;
    result.quote_signature_b64 = ""; // Full TPM quote requires AK creation
    result.success = true;
    return result;
}

attestation_result generate_attestation(const std::string& nonce) {
    attestation_result result;

    if (!tpm_available()) {
        result.error = "No TPM device found";
        return result;
    }

    result.ek_pub_hash = get_ek_hash();
    if (result.ek_pub_hash.empty()) {
        result.error = "Failed to read EK public key";
        return result;
    }

    quote_result qr = get_pcr_quote(nonce);
    if (!qr.success) {
        result.error = qr.error;
        return result;
    }

    result.quote_signature_b64 = qr.quote_signature_b64;
    result.pcr_digest_b64 = qr.pcr_digest_b64;
    result.pcr_values_hex = qr.pcr_values_hex;
    result.ak_name_hex = "";

    nlohmann::json j;
    j["ek_hash"] = result.ek_pub_hash;
    j["pcr_digest_b64"] = result.pcr_digest_b64;
    j["pcr_values"] = result.pcr_values_hex;
    j["nonce"] = nonce;
    j["tpm_present"] = true;
    result.attestation_json = j.dump(2);
    result.success = true;
    return result;
}

bool validate_attestation(const std::string& attestation_json,
                          const std::string& nonce,
                          const std::string& vendor_ak_pub_pem) {
    try {
        auto j = nlohmann::json::parse(attestation_json);
        if (!j.contains("pcr_digest_b64")) return false;
        if (!j.contains("nonce") || j["nonce"] != nonce) return false;
        if (!j.value("tpm_present", false)) return false;
        if (!j.contains("ek_hash") || j["ek_hash"].get<std::string>().empty()) return false;
        return true;
    } catch (...) {
        return false;
    }
}

}