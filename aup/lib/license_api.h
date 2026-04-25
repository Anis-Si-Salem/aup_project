#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const char* get_fingerprint(void);
const char* get_machine_id(void);
const char* get_cpu_info(void);
const char* get_tpm_ek_hash(void);
int is_tpm_available(void);

int verify_license_json(const char* license_json);
int check_fingerprint_match(const char* embedded_fp, const char* current_fp);
int verify_license_signature(const char* data, const char* signature, const char* pubkey);

const char* get_error_message(void);
void clear_error(void);

void logger_init(const char* fingerprint);
void logger_init_path(const char* fingerprint, const char* log_path);
void logger_log_event(const char* event, const char* detail);
void logger_log_startup(void);
void logger_log_hw_validation(const char* fp_hash, int match);
void logger_log_tamper(const char* reason);
void logger_log_tpm(const char* event, int success);
void logger_log_license(const char* action, int success);
void logger_log_seal(const char* action, int success);
void logger_shutdown(void);

#ifdef __cplusplus
}
#endif