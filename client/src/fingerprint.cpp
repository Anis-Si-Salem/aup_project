#include "fingerprint.h"
#include "tpm_attest.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace fingerprint {

static std::string read_sysfs(const std::string& path) {
    std::ifstream f(path);
    std::string val;
    if (f.is_open() && std::getline(f, val)) {
        while (!val.empty() && (val.back() == '\n' || val.back() == '\r' || val.back() == ' '))
            val.pop_back();
    }
    return val;
}

static bool tpm_device_exists() {
    return std::filesystem::exists("/dev/tpm0") ||
           std::filesystem::exists("/dev/tpmrm0");
}

hardware_ids collect_all() {
    hardware_ids ids{};
    ids.tpm_available = false;
    ids.tpm_required = false;

    // TPM/vTPM detection - MANDATORY for security
    if (tpm_device_exists()) {
        ids.tpm_available = true;
        ids.tpm_required = true;  // TPM is mandatory for licensing
        
        std::string ek = read_sysfs("/sys/class/tpm/tpm0/device/parameters");
        if (ek.empty()) {
            ek = "TPM-DEVICE-PRESENT";
        }
        ids.tpm_ek = ek;

        std::string ek_hash = tpm_attest::get_ek_hash();
        if (!ek_hash.empty()) {
            ids.tpm_ek_hash = ek_hash;
        }
    } else {
        // NO TPM = NO LICENSE
        // We still collect other IDs but mark as insecure
        ids.tpm_available = false;
        ids.tpm_required = true;  // REJECT if no TPM
    }

    // Machine ID (for compatibility only - NOT USED for binding if TPM exists)
    ids.machine_id = read_sysfs("/etc/machine-id");

    // DMI product UUID (for compatibility only)
    ids.product_uuid = read_sysfs("/sys/class/dmi/id/product_uuid");

    // CPU info (for display only)
    {
        std::ifstream f("/proc/cpuinfo");
        std::string line;
        std::string model;
        while (f.is_open() && std::getline(f, line)) {
            if (line.find("model name") != std::string::npos) {
                auto colon = line.find(':');
                if (colon != std::string::npos) {
                    model = line.substr(colon + 1);
                    while (!model.empty() && model.front() == ' ') model.erase(model.begin());
                    break;
                }
            }
        }
        ids.cpu_info = model;
    }

    // Network MACs
    {
        std::string base = "/sys/class/net";
        for (const auto& entry : std::filesystem::directory_iterator(base)) {
            std::string name = entry.path().filename();
            if (name == "lo") continue;
            std::ifstream addr(entry.path() / "address");
            std::string mac;
            if (std::getline(addr, mac)) {
                while (!mac.empty() && (mac.back() == '\n' || mac.back() == '\r'))
                    mac.pop_back();
                if (!mac.empty() && mac != "00:00:00:00:00:00") {
                    ids.macs.emplace_back(name, mac);
                }
            }
        }
    }

    return ids;
}

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += hex[(data[i] >> 4) & 0xf];
        out += hex[data[i] & 0xf];
    }
    return out;
}

std::string compute_hash(const hardware_ids& ids) {
    nlohmann::json j;
    
    // TPM EK hash is MANDATORY for secure binding
    if (ids.tpm_available && !ids.tpm_ek_hash.empty()) {
        j["tpm_ek_hash"] = ids.tpm_ek_hash;
    } else {
        // No TPM = insecure, mark accordingly
        j["tpm_ek_hash"] = "NO_TPM";
    }
    
    // Compatibility fields (used for display only, NOT for binding)
    if (!ids.machine_id.empty()) j["machine_id"] = ids.machine_id;
    if (!ids.product_uuid.empty()) j["product_uuid"] = ids.product_uuid;
    if (!ids.cpu_info.empty()) j["cpu_info"] = ids.cpu_info;
    
    std::vector<std::pair<std::string, std::string>> macs;
    for (auto& [iface, mac] : ids.macs) {
        j["mac_" + iface] = mac;
    }

    std::string canonical = j.dump(-1, ' ', true);
    
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(canonical.data()), 
          canonical.size(), hash);
    
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

std::string compute_fingerprint_hash() {
    hardware_ids ids = collect_all();
    return compute_hash(ids);
}

hardware_ids get_current_hardware() {
    return collect_all();
}

}