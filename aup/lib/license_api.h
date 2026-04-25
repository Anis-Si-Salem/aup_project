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

#ifdef __cplusplus
}
#endif