#include <climits>
#include <cstring>
#include <limits>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

#include <openssl/crypto.h>

#include "fingerprint.h"
#include "verifier.h"
#include "app_loader.h"
#include "anti_re.h"
#include "license_embed.h"
#include "tpm_attest.h"
#include "tpm_seal.h"
#include "secure_logger.h"

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string get_exe_dir() {
    char exe[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) return "./";
    exe[len] = '\0';
    std::string dir(exe);
    auto slash = dir.rfind('/');
    return (slash != std::string::npos) ? dir.substr(0, slash + 1) : "./";
}

int main(int argc, char* argv[]) {
    anti_re::init();
    anti_re::start_background_monitor();

    secure_logger::log_startup();

    license_embed::embedded_license emb;
    if (license_embed::read_embedded(emb)) {
        if (!license_embed::verify_embedded_integrity(emb)) {
            std::cerr << "\n  LICENSE INTEGRITY VIOLATION\n  Tampering detected.\n\n";
            secure_logger::log_tamper("embedded_integrity_check_failed");
            return 1;
        }

        if (!license_embed::verify_embedded_signature(emb)) {
            std::cerr << "\n  LICENSE SIGNATURE INVALID\n  Cryptographic verification failed.\n\n";
            secure_logger::log_tamper("embedded_signature_invalid");
            return 1;
        }

        if (emb.expiry_timestamp > 0) {
            time_t now = time(nullptr);
            if (static_cast<time_t>(emb.expiry_timestamp) < now) {
                std::cerr << "\n  LICENSE EXPIRED on " << ctime(&now) << "\n";
                secure_logger::log_license("expired", false);
                return 1;
            }
            int days = static_cast<int>((static_cast<time_t>(emb.expiry_timestamp) - now) / 86400);
            std::cout << "  License expires in " << days << " days.\n";
        }

        std::string fp_hash = fingerprint::compute_fingerprint_hash();
        if (strlen(emb.fp_hash) > 0 && std::string(emb.fp_hash) != fp_hash) {
            std::cerr << "\n  FINGERPRINT MISMATCH\n";
            if (tpm_attest::tpm_available()) {
                std::cerr << "  Possible unauthorized disk cloning.\n";
                std::cerr << "  TPM attestation indicates hardware change.\n";
            }
            secure_logger::log_hw_validation(fp_hash, false);
            std::cerr << "\n";
            return 1;
        }
        secure_logger::log_hw_validation(fp_hash, true);

        if (emb.canonical_json_len > 0) {
            secure_logger::init(std::string(emb.fp_hash));
        }

        std::cout << "\n  License OK. Launching application...\n\n";
        secure_logger::log_license("launch", true);
        int rc = app_loader::load_and_run("app_core.enc");
        secure_logger::shutdown();
        return rc < 0 ? 1 : rc;
    }

    std::cout << "\n";
    std::cout << "  ╔══════════════════════════════════════════════╗\n";
    std::cout << "  ║     ON-PREMISE SECURITY INSTALLER            ║\n";
    std::cout << "  ╚══════════════════════════════════════════════╝\n\n";

    std::cout << "  ━━━ Step 1: Hardware Fingerprint ━━━━━━━━━━━━━━━━\n\n";
    fingerprint::hardware_ids hw = fingerprint::collect_all();

    std::cout << "  TPM/vTPM:    " << (hw.tpm_available ? "DETECTED" : "not available") << "\n";
    if (!hw.tpm_available) {
        std::cerr << "\n  ERROR: TPM is REQUIRED for this software.\n";
        std::cerr << "  This machine has no TPM (or /dev/tpm0 doesn't exist).\n";
        std::cerr << "  Cannot proceed without TPM-based hardware binding.\n\n";
        return 1;
    }

    if (!hw.tpm_ek_hash.empty()) {
        std::cout << "  TPM EK Hash: " << hw.tpm_ek_hash << " (REQUIRED)\n";
        std::cout << "  → License will be bound to this specific TPM.\n";
    }
    if (!hw.machine_id.empty())
        std::cout << "  Machine ID:  " << hw.machine_id << "\n";
    if (!hw.product_uuid.empty())
        std::cout << "  Product UUID: " << hw.product_uuid << "\n";
    if (!hw.cpu_info.empty())
        std::cout << "  CPU:          " << hw.cpu_info << "\n";
    for (auto& [iface, mac] : hw.macs)
        std::cout << "  MAC (" << iface << "):  " << mac << "\n";

    std::string fp_hash = fingerprint::compute_hash(hw);

    std::cout << "\n  ┌──────────────────────────────────────────────────┐\n";
    std::cout << "  │  FINGERPRINT                                    │\n";
    std::cout << "  │                                                  │\n";
    std::cout << "  │  " << fp_hash << "  │\n";
    std::cout << "  │                                                  │\n";
    std::cout << "  │  Send this hash to your vendor to receive a     │\n";
    std::cout << "  │  signed license file.                            │\n";
    std::cout << "  └──────────────────────────────────────────────────┘\n\n";

    std::cout << "  Press ENTER when you have the license files ready...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "\n  ━━━ Step 2: Provide License ━━━━━━━━━━━━━━━━━━━━━\n\n";

    std::string license_path = "license.json";
    std::string pubkey_path = "pubkey.pem";

    if (argc >= 3) {
        license_path = argv[1];
        pubkey_path = argv[2];
    } else {
        auto prompt = [](const char* label, const char* def) -> std::string {
            while (true) {
                std::cout << "  " << label << " [" << def << "]: ";
                std::cout.flush();
                std::string input;
                if (!std::getline(std::cin, input)) std::exit(1);
                while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) input.erase(input.begin());
                while (!input.empty() && (input.back() == ' ' || input.back() == '\t')) input.pop_back();
                if (input.empty()) input = def;
                std::ifstream t(input, std::ios::binary);
                if (t.is_open()) return input;
                std::cerr << "  File not found: " << input << "\n";
            }
        };
        license_path = prompt("License JSON", license_path.c_str());
        pubkey_path = prompt("Public Key  ", pubkey_path.c_str());
    }

    std::string license_json = read_file(license_path);
    std::string pubkey_pem = read_file(pubkey_path);
    if (license_json.empty() || pubkey_pem.empty()) {
        std::cerr << "\n  ERROR: Could not read license or public key.\n\n";
        return 1;
    }

    std::cout << "\n  ━━━ Step 3: License Verification ━━━━━━━━━━━━━━━━━━\n\n";
    std::cout << "  Checking signature...\n";

    verifier::license_data lic;
    if (!verifier::verify_license(license_json, pubkey_pem, lic)) {
        std::cerr << "  INVALID LICENSE - signature verification failed.\n";
        secure_logger::log_license("verify", false);
        return 1;
    }
    std::cout << "  Signature verified.\n";

    if (lic.fingerprint != fp_hash) {
        std::cerr << "  FINGERPRINT MISMATCH - license is for a different machine.\n";
        std::cerr << "    License bound to:  " << lic.fingerprint << "\n";
        std::cerr << "    This machine:     " << fp_hash << "\n\n";
        secure_logger::log_hw_validation(fp_hash, false);
        return 1;
    }
    std::cout << "  Fingerprint matches this machine.\n";
    secure_logger::log_hw_validation(fp_hash, true);

    if (verifier::is_expired(lic)) {
        std::cerr << "  License EXPIRED on " << lic.expires_at << "\n\n";
        return 1;
    }

    int days = verifier::days_remaining(lic);
    std::cout << "  License valid for " << days << " more days.\n";

    std::string canonical_json = verifier::strip_signature(license_json);
    std::string signature_b64 = verifier::extract_signature(license_json);

    std::cout << "\n  ┌──────────────────────────────────────────────────┐\n";
    std::cout << "  │  LICENSE VERIFIED                                │\n";
    std::cout << "  │                                                  │\n";
    std::cout << "  │  Max Users:   " << lic.max_users << "\n";
    std::cout << "  │  Issued:      " << lic.issued_at << "\n";
    std::cout << "  │  Expires:     " << lic.expires_at << " (" << days << " days)\n";
    std::cout << "  └──────────────────────────────────────────────────┘\n\n";

    std::cout << "  Press ENTER to install and start the application...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "\n  ━━━ Step 4: Installation ━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

    char exe_path[4096] = {};
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_len <= 0) {
        std::cerr << "  Cannot determine executable path.\n";
        return 1;
    }
    exe_path[exe_len] = '\0';

    std::string install_dir = "/usr/local/bin";
    std::string exe_dir = get_exe_dir();

    std::string vendor_key_path = exe_dir + "app_core.key";
    uint8_t vendor_key[32] = {};
    bool has_vendor_key = false;
    {
        std::ifstream vkf(vendor_key_path, std::ios::binary);
        if (vkf.is_open() && vkf.read(reinterpret_cast<char*>(vendor_key), 32)) {
            has_vendor_key = true;
            std::cout << "  Vendor encryption key loaded.\n";
        } else {
            std::cerr << "  WARNING: Cannot read vendor key from " << vendor_key_path << "\n";
            std::cerr << "  Payload will be installed without re-encryption.\n";
        }
    }

    std::string install_path = install_dir + "/secure_app";
    uint8_t machine_key[32] = {};
    std::string enc_src_path = exe_dir + "app_core.enc";
    std::string enc_dst_path = install_dir + "/app_core.enc";
    std::string tss_key_path = install_dir + "/app_core.enc.key.tss";
    std::string reenc_tmp_path;

    if (has_vendor_key) {
        reenc_tmp_path = "/tmp/secure_app_reenc_" + std::to_string(getpid()) + ".enc";
        if (!app_loader::re_encrypt_payload(enc_src_path, vendor_key, machine_key, reenc_tmp_path)) {
            std::cerr << "  Failed to re-encrypt payload.\n";
            OPENSSL_cleanse(vendor_key, sizeof(vendor_key));
            return 1;
        }
        std::cout << "  Payload re-encrypted with machine-specific key.\n";
        OPENSSL_cleanse(vendor_key, sizeof(vendor_key));

        if (tpm_attest::tpm_available()) {
            std::vector<uint8_t> key_vec(machine_key, machine_key + 32);
            auto seal_result = tpm_seal::seal_license_key(key_vec);
            if (seal_result.success) {
                std::ofstream kf(tss_key_path, std::ios::binary);
                if (kf.is_open()) {
                    kf.write(reinterpret_cast<const char*>(seal_result.sealed_data.data()),
                             seal_result.sealed_data.size());
                    std::cout << "  AES key TPM-sealed successfully.\n";
                    secure_logger::log_seal("seal_key", true);
                } else {
                    std::cerr << "  Failed to write sealed key file.\n";
                    secure_logger::log_seal("seal_key_write", false);
                }
            } else {
                std::cerr << "  TPM seal failed: " << seal_result.error << "\n";
                std::cerr << "  Storing key in fallback mode.\n";
                secure_logger::log_seal("seal_key", false);
                tss_key_path = install_dir + "/app_core.enc.key.bin";
                std::ofstream kf(tss_key_path, std::ios::binary);
                kf.write(reinterpret_cast<const char*>(machine_key), 32);
            }
        } else {
            std::cerr << "  No TPM - storing key in fallback mode.\n";
            secure_logger::log_tpm("seal_no_tpm", false);
            tss_key_path = install_dir + "/app_core.enc.key.bin";
            std::ofstream kf(tss_key_path, std::ios::binary);
            kf.write(reinterpret_cast<const char*>(machine_key), 32);
        }
        OPENSSL_cleanse(machine_key, sizeof(machine_key));
    }

    std::cout << "  Embedding license into binary...\n";

    license_embed::embedded_license lic_data = {};
    memcpy(lic_data.magic, "SECURELIC01", 11);
    lic_data.version = 1;
    lic_data.expiry_timestamp = lic.expiry_timestamp;
    strncpy(lic_data.fp_hash, fp_hash.c_str(), sizeof(lic_data.fp_hash) - 1);

    {
        auto sig_bytes = verifier::b64_decode_raw(signature_b64);
        if (sig_bytes.size() == 64) {
            memcpy(lic_data.ed25519_signature, sig_bytes.data(), 64);
        }
    }

    strncpy(lic_data.payload, canonical_json.c_str(),
            std::min(canonical_json.size(), sizeof(lic_data.payload) - 1));
    lic_data.canonical_json_len = static_cast<uint16_t>(
        std::min(canonical_json.size(), sizeof(lic_data.payload) - 1));

    if (!license_embed::patch_binary(exe_path, install_path, lic_data)) {
        std::cout << "  Installing to current directory instead...\n";
        install_path = "./secure_app_installed";
        install_dir = ".";
        if (!license_embed::patch_binary(exe_path, install_path, lic_data)) {
            std::cerr << "  Failed to patch binary.\n";
            return 1;
        }
    }
    std::cout << "  Binary patched: " << install_path << "\n";

    {
        std::string src_path = has_vendor_key ? reenc_tmp_path : enc_src_path;
        std::ifstream src_enc(src_path, std::ios::binary);
        if (src_enc.is_open()) {
            std::ofstream dst_enc(enc_dst_path, std::ios::binary);
            dst_enc << src_enc.rdbuf();
            std::cout << "  Encrypted payload installed.\n";
        }
    }

    if (has_vendor_key && !reenc_tmp_path.empty()) {
        unlink(reenc_tmp_path.c_str());
    }

    secure_logger::init(std::string(lic_data.fp_hash));
    secure_logger::log_license("install", true);

    std::cout << "  Installation complete.\n\n";
    std::cout << "  Run '" << install_path << "' to start the application.\n\n";

    secure_logger::shutdown();
    return 0;
}