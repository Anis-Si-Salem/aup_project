#include "tpm_seal.h"
#include "tpm_attest.h"

#include <cstring>
#include <fstream>
#include <filesystem>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

namespace tpm_seal {

seal_result seal_data(const std::vector<uint8_t>& data,
                      const std::string& pcr_policy) {
    seal_result result;
    if (!tpm_attest::tpm_available()) {
        result.error = "No TPM available";
        return result;
    }

    ESYS_CONTEXT* ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        result.error = "ESYS init failed";
        return result;
    }

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        Esys_Finalize(&ctx);
        result.error = "TPM startup failed";
        return result;
    }

    ESYS_TR parent_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* out_pub_primary = nullptr;
    TPM2B_CREATION_DATA* creation_data = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* creation_ticket = nullptr;

    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            nullptr, nullptr, nullptr, nullptr,
                            &parent_handle, &out_pub_primary,
                            &creation_data, &creation_hash, &creation_ticket);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        result.error = "Failed to create primary key";
        return result;
    }
    Esys_Free(out_pub_primary);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    TPM2B_SENSITIVE_CREATE sens = {};
    sens.sensitive.data.size = std::min(data.size(), (size_t)128);
    memcpy(sens.sensitive.data.buffer, data.data(), sens.sensitive.data.size);

    TPM2B_PUBLIC pub_template = {};
    pub_template.size = 0;
    pub_template.publicArea.type = TPM2_ALG_KEYEDHASH;
    pub_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    pub_template.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
                                              TPMA_OBJECT_FIXEDPARENT;
    pub_template.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    TPML_PCR_SELECTION pcr_sel = {};
    pcr_sel.count = 1;
    pcr_sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_sel.pcrSelections[0].sizeofSelect = 3;
    pcr_sel.pcrSelections[0].pcrSelect[0] = 0x01;

    TPM2B_DATA outside_info = {};

    TPM2B_PUBLIC* out_pub = nullptr;
    TPM2B_PRIVATE* out_priv = nullptr;
    TPM2B_CREATION_DATA* obj_creation_data = nullptr;
    TPM2B_DIGEST* obj_creation_hash = nullptr;
    TPMT_TK_CREATION* obj_creation_ticket = nullptr;

    rc = Esys_Create(ctx, parent_handle,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &sens, &pub_template, &outside_info, &pcr_sel,
                     &out_priv, &out_pub,
                     &obj_creation_data, &obj_creation_hash, &obj_creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to create sealed object";
        return result;
    }

    std::vector<uint8_t> priv_buf(4096);
    std::vector<uint8_t> pub_buf(4096);
    size_t priv_offset = 0;
    size_t pub_offset = 0;

    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(out_priv, priv_buf.data(), priv_buf.size(), &priv_offset);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_priv); Esys_Free(out_pub);
        Esys_Free(obj_creation_data); Esys_Free(obj_creation_hash); Esys_Free(obj_creation_ticket);
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to marshal private key";
        return result;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(out_pub, pub_buf.data(), pub_buf.size(), &pub_offset);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_priv); Esys_Free(out_pub);
        Esys_Free(obj_creation_data); Esys_Free(obj_creation_hash); Esys_Free(obj_creation_ticket);
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to marshal public key";
        return result;
    }

    size_t total = 4 + priv_offset + 4 + pub_offset;
    result.sealed_data.resize(total);
    size_t off = 0;
    uint32_t priv_sz = static_cast<uint32_t>(priv_offset);
    memcpy(result.sealed_data.data() + off, &priv_sz, 4); off += 4;
    memcpy(result.sealed_data.data() + off, priv_buf.data(), priv_offset); off += priv_offset;
    uint32_t pub_sz = static_cast<uint32_t>(pub_offset);
    memcpy(result.sealed_data.data() + off, &pub_sz, 4); off += 4;
    memcpy(result.sealed_data.data() + off, pub_buf.data(), pub_offset);

    Esys_Free(out_priv);
    Esys_Free(out_pub);
    Esys_Free(obj_creation_data);
    Esys_Free(obj_creation_hash);
    Esys_Free(obj_creation_ticket);
    Esys_FlushContext(ctx, parent_handle);
    Esys_Finalize(&ctx);
    result.success = true;
    return result;
}

unseal_result unseal_data(const std::vector<uint8_t>& sealed_blob) {
    unseal_result result;
    if (!tpm_attest::tpm_available()) {
        result.error = "No TPM available";
        return result;
    }

    if (sealed_blob.size() < 8) {
        result.error = "Sealed blob too small";
        return result;
    }

    ESYS_CONTEXT* ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        result.error = "ESYS init failed";
        return result;
    }

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        Esys_Finalize(&ctx);
        result.error = "TPM startup failed";
        return result;
    }

    ESYS_TR parent_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* out_pub_primary = nullptr;
    TPM2B_CREATION_DATA* creation_data = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* creation_ticket = nullptr;

    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            nullptr, nullptr, nullptr, nullptr,
                            &parent_handle, &out_pub_primary,
                            &creation_data, &creation_hash, &creation_ticket);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        result.error = "Failed to create primary key";
        return result;
    }
    Esys_Free(out_pub_primary);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    size_t off = 0;
    uint32_t priv_sz;
    memcpy(&priv_sz, sealed_blob.data() + off, 4); off += 4;

    if (off + priv_sz > sealed_blob.size()) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Sealed blob corrupt (priv)";
        return result;
    }

    TPM2B_PRIVATE priv = {};
    size_t priv_offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(sealed_blob.data() + off, priv_sz, &priv_offset, &priv);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to unmarshal private key";
        return result;
    }
    off += priv_sz;

    uint32_t pub_sz;
    memcpy(&pub_sz, sealed_blob.data() + off, 4); off += 4;

    if (off + pub_sz > sealed_blob.size()) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Sealed blob corrupt (pub)";
        return result;
    }

    TPM2B_PUBLIC pub = {};
    size_t pub_offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(sealed_blob.data() + off, pub_sz, &pub_offset, &pub);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to unmarshal public key";
        return result;
    }

    ESYS_TR sealed_handle = ESYS_TR_NONE;
    rc = Esys_Load(ctx, parent_handle,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &priv, &pub,
                   &sealed_handle);

    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Failed to load sealed object (PCR mismatch?)";
        return result;
    }

    TPM2B_SENSITIVE_DATA* unsealed = nullptr;
    rc = Esys_Unseal(ctx, sealed_handle,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &unsealed);

    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, sealed_handle);
        Esys_FlushContext(ctx, parent_handle);
        Esys_Finalize(&ctx);
        result.error = "Unseal failed (PCR policy not satisfied?)";
        return result;
    }

    result.data.assign(unsealed->buffer, unsealed->buffer + unsealed->size);
    Esys_Free(unsealed);
    Esys_FlushContext(ctx, sealed_handle);
    Esys_FlushContext(ctx, parent_handle);
    Esys_Finalize(&ctx);
    result.success = true;
    return result;
}

seal_result seal_license_key(const std::vector<uint8_t>& aes_key,
                              const std::string& pcr_bank) {
    return seal_data(aes_key, pcr_bank);
}

unseal_result unseal_license_key(const std::vector<uint8_t>& sealed_blob,
                                  const std::string& pcr_bank) {
    return unseal_data(sealed_blob);
}

bool verify_pcr_integrity(const std::string& expected_pcr_hash,
                           int pcr_index,
                           const std::string& pcr_bank) {
    std::string pcrs = tpm_attest::get_pcr_values(pcr_index + 1);
    return pcrs.find(expected_pcr_hash) != std::string::npos;
}

std::string get_current_pcr_hash(int pcr_index, const std::string& pcr_bank) {
    std::string pcrs = tpm_attest::get_pcr_values(pcr_index + 1);
    std::string prefix = "PCR" + std::to_string(pcr_index) + ": ";
    auto pos = pcrs.find(prefix);
    if (pos == std::string::npos) return "";
    auto end = pcrs.find('\n', pos);
    return pcrs.substr(pos + prefix.size(), end - pos - prefix.size());
}

}