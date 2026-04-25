#include <iostream>
#include "fingerprint.h"

int main() {
    fingerprint::hardware_ids hw = fingerprint::collect_all();
    std::string fp_hash = fingerprint::compute_hash(hw);

    std::cout << "Hardware Fingerprint: " << fp_hash << "\n\n";
    std::cout << "Details:\n";
    std::cout << "  TPM Available: " << (hw.tpm_available ? "yes" : "no") << "\n";
    std::cout << "  TPM Required: " << (hw.tpm_required ? "yes" : "no") << "\n";
    std::cout << "  TPM EK Hash: " << hw.tpm_ek_hash << "\n";
    std::cout << "  Machine ID: " << hw.machine_id << "\n";
    std::cout << "  Product UUID: " << hw.product_uuid << "\n";
    std::cout << "  CPU Info: " << hw.cpu_info << "\n";
    for (const auto& m : hw.macs) {
        std::cout << "  MAC: " << m.first << " (" << m.second << ")\n";
    }

    return 0;
}