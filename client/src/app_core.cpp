#include <fstream>
#include <iostream>
#include <ctime>

#include "anti_re.h"
#include "license_embed.h"
#include "secure_logger.h"

extern "C" __attribute__((visibility("default"))) int app_main() {
    if (anti_re::check_tracer_pid() || anti_re::check_breakpoint()) {
        secure_logger::log_tamper("startup_tracer_or_breakpoint");
        return 1;
    }

    license_embed::embedded_license emb;
    if (!license_embed::read_embedded(emb)) {
        std::cerr << "\n  ERROR: No valid license found.\n";
        std::cerr << "  Contact your vendor to obtain a valid license.\n\n";
        secure_logger::log_license("no_embedded_license", false);
        return 1;
    }

    if (!license_embed::verify_embedded_integrity(emb)) {
        secure_logger::log_tamper("embedded_integrity_fail");
        return 1;
    }

    if (!license_embed::verify_embedded_signature(emb)) {
        secure_logger::log_tamper("embedded_signature_invalid");
        return 1;
    }

    time_t now = time(nullptr);
    if (static_cast<time_t>(emb.expiry_timestamp) < now) {
        time_t exp_t = static_cast<time_t>(emb.expiry_timestamp);
        std::cerr << "\n  APPLICATION EXPIRED\n";
        std::cerr << "  License expired on: " << ctime(&exp_t);
        std::cerr << "  Contact vendor for renewal.\n\n";
        secure_logger::log_license("expired_at_startup", false);
        return 1;
    }

    anti_re::set_license_expiry(emb.expiry_timestamp);
    anti_re::start_background_monitor();

    int days = static_cast<int>((static_cast<time_t>(emb.expiry_timestamp) - now) / 86400);
    std::cout << "\n  ═══ APPLICATION CORE ═════════════════════════\n\n";
    std::cout << "  License valid for " << days << " days\n";

    if (days <= 30) {
        std::cout << "  WARNING: License expires in " << days << " days!\n";
    }
    if (days <= 7) {
        std::cout << "  CRITICAL: License expires very soon!\n";
    }

    if (emb.expiry_timestamp > 0) {
        secure_logger::init(std::string(emb.fp_hash));
    }

    std::cout << "\n  Application running. Will auto-terminate on expiry.\n";
    std::cout << "  Press Enter to exit.\n";
    std::cin.get();

    anti_re::stop_background_monitor();
    std::cout << "  ═══ APPLICATION SHUTDOWN ══════════════════════\n";
    secure_logger::shutdown();
    return 0;
}