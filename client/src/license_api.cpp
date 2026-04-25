#include "license_api.h"
#include "fingerprint.h"
#include "verifier.h"
#include "secure_logger.h"

#include <cstring>
#include <string>
#include <mutex>

static std::string g_last_error;
static std::mutex g_mutex;

static void set_error(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_last_error = msg;
}

extern "C" {

const char* get_error_message(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_last_error.empty() ? "" : g_last_error.c_str();
}

void clear_error(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_last_error.clear();
}

const char* get_fingerprint(void) {
    clear_error();
    static std::string fp;
    try {
        fingerprint::hardware_ids hw = fingerprint::collect_all();
        fp = fingerprint::compute_hash(hw);
        if (fp.empty()) {
            set_error("Failed to compute fingerprint");
            return nullptr;
        }
        return fp.c_str();
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return nullptr;
    }
}

const char* get_machine_id(void) {
    clear_error();
    static std::string mid;
    try {
        fingerprint::hardware_ids hw = fingerprint::collect_all();
        mid = hw.machine_id;
        return mid.c_str();
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return nullptr;
    }
}

const char* get_cpu_info(void) {
    clear_error();
    static std::string cpu;
    try {
        fingerprint::hardware_ids hw = fingerprint::collect_all();
        cpu = hw.cpu_info;
        return cpu.c_str();
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return nullptr;
    }
}

const char* get_tpm_ek_hash(void) {
    clear_error();
    static std::string ek;
    try {
        fingerprint::hardware_ids hw = fingerprint::collect_all();
        ek = hw.tpm_ek_hash;
        return ek.c_str();
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return nullptr;
    }
}

int is_tpm_available(void) {
    try {
        fingerprint::hardware_ids hw = fingerprint::collect_all();
        return hw.tpm_available ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int verify_license_json(const char* license_json) {
    clear_error();
    if (!license_json) {
        set_error("License JSON is null");
        return 0;
    }
    try {
        std::string json_str(license_json);
        std::string pubkey = verifier::get_embedded_pubkey();
        verifier::license_data lic;
        
        bool valid = verifier::verify_license(json_str, pubkey, lic);
        if (!valid) {
            set_error("License verification failed");
            return 0;
        }
        
        if (lic.fingerprint.empty() || lic.expires_at.empty()) {
            set_error("Invalid license: missing fingerprint or expiry");
            return 0;
        }
        return 1;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return 0;
    }
}

int check_fingerprint_match(const char* embedded_fp, const char* current_fp) {
    clear_error();
    if (!embedded_fp || !current_fp) {
        set_error("Fingerprint parameter is null");
        return 0;
    }
    std::string emb(embedded_fp);
    std::string cur(current_fp);
    return (emb == cur) ? 1 : 0;
}

int verify_license_signature(const char* data, const char* signature, const char* pubkey) {
    clear_error();
    if (!data || !signature || !pubkey) {
        set_error("Signature parameter is null");
        return 0;
    }
    try {
        std::string data_str(data);
        std::string sig_str(signature);
        std::string key_str(pubkey);
        
        verifier::license_data lic;
        bool valid = verifier::verify_license(data_str, key_str, lic);
        return valid ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return 0;
    }
}

void logger_init(const char* fingerprint) {
    if (!fingerprint) return;
    secure_logger::init(std::string(fingerprint));
}

void logger_init_path(const char* fingerprint, const char* log_path) {
    if (!fingerprint) return;
    std::string path = log_path ? log_path : "";
    secure_logger::init(std::string(fingerprint), path);
}

void logger_log_event(const char* event, const char* detail) {
    if (!event) return;
    std::string d = detail ? detail : "";
    secure_logger::log(std::string(event), d);
}

void logger_log_startup(void) {
    secure_logger::log_startup();
}

void logger_log_hw_validation(const char* fp_hash, int match) {
    secure_logger::log_hw_validation(fp_hash ? fp_hash : "", match != 0);
}

void logger_log_tamper(const char* reason) {
    secure_logger::log_tamper(reason ? reason : "unknown");
}

void logger_log_tpm(const char* event, int success) {
    secure_logger::log_tpm(event ? event : "", success != 0);
}

void logger_log_license(const char* action, int success) {
    secure_logger::log_license(action ? action : "", success != 0);
}

void logger_log_seal(const char* action, int success) {
    secure_logger::log_seal(action ? action : "", success != 0);
}

void logger_shutdown(void) {
    secure_logger::shutdown();
}

}