# AUP Architecture — Secure Audit Logging & Encryption

## Overview

The AUP system uses a layered encryption architecture to protect audit logs at rest. Every significant event (startup, license check, tamper detection, TPM operations) is written to an encrypted, chained log file. Only the vendor possessing the RSA private key can decrypt and verify these logs.

## Audit Log Encryption Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Protected Application (Go)                      │
│                                                                     │
│  main.go → license.LoggerInit(fp)                                  │
│           → license.LoggerLogStartup()                              │
│           → license.LoggerLogLicense("verify", true)               │
│           → license.LoggerLogHWValidation(fp, true)                 │
│           → license.LoggerShutdown()  (defer)                      │
│                                                                     │
│           │ cgo                                                     │
│           ▼                                                         │
│  ┌─────────────────────────────────────────┐                       │
│  │  libsecure_app_core.so (C++)            │                       │
│  │                                          │                       │
│  │  secure_logger::init(fp)                │                       │
│  │    ├─ Generate random AES-256 key       │                       │
│  │    ├─ Generate random chain key          │                       │
│  │    ├─ RSA-OAEP encrypt AES key           │                       │
│  │    ├─ RSA-OAEP encrypt chain key         │                       │
│  │    └─ Write AUDT v2 header               │                       │
│  │                                          │                       │
│  │  secure_logger::log(event, detail)       │                       │
│  │    ├─ Build entry: TIMESTAMP | FP:hash   │                       │
│  │    │   | EVENT | DETAIL | CHAIN:hmac     │                       │
│  │    ├─ HMAC-SHA256(prev_sig, chain_key)    │                       │
│  │    ├─ AES-256-GCM encrypt (random IV)     │                       │
│  │    └─ Append [len][IV][ciphertext][tag]   │                       │
│  └─────────────────────────────────────────┘                       │
│                                                                     │
│           ▼ app_audit.enc                                          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     Vendor (Node.js Server)                         │
│                                                                     │
│  POST /api/license/renew                                            │
│    ├─ Upload app_audit.enc                                          │
│    ├─ Parse AUDT v2 binary header                                   │
│    ├─ RSA-OAEP decrypt → AES-256 key                                │
│    ├─ RSA-OAEP decrypt → chain key (v2)                              │
│    ├─ AES-256-GCM decrypt each entry                                 │
│    ├─ Verify chain signatures (HMAC-SHA256)                          │
│    ├─ Extract fingerprint → find license                             │
│    └─ Renew license, store decrypted entries                         │
│                                                                     │
│  GET /api/license/audit/:fingerprint → view stored logs             │
└─────────────────────────────────────────────────────────────────────┘
```

## Binary Log File Format (AUDT v2)

```
Header:
┌──────────┬─────────┬──────────┬──────────────┬───────────────┬───────────────┬──────────────────┐
│ Magic    │ Version │ FP Len   │ Fingerprint  │ Enc Key Len   │ Enc AES Key   │ Enc Chain Key    │
│ "AUDT"   │ (1 byte)│ (1 byte)│ (FP Len B)   │ (2 bytes LE)  │ (Enc Key Len) │ Len (2B) + Data  │
│ 4 bytes  │ = 2     │          │              │               │               │                  │
└──────────┴─────────┴──────────┴──────────────┴───────────────┴───────────────┴──────────────────┘

Each Entry:
┌──────────┬───────────┬──────────────────────┬───────────┐
│ Total Len│ IV        │ Ciphertext            │ GCM Tag   │
│ (4B LE)  │ (12 bytes)│ (Total-12-16 bytes)  │ (16 bytes)│
└──────────┴───────────┴──────────────────────┴───────────┘

Decrypted Entry Format:
TIMESTAMP | FP:fingerprint | EVENT | DETAIL | CHAIN:hmac_hex
```

## Encryption Algorithms

| Component          | Algorithm           | Key Size | Purpose                          |
|--------------------|---------------------|----------|----------------------------------|
| Session Key        | RSA-2048-OAEP-SHA256| 2048-bit | Wraps per-session AES-256 key    |
| Chain Key          | RSA-2048-OAEP-SHA256| 2048-bit | Wraps per-session HMAC key (v2)  |
| Entry Encryption   | AES-256-GCM         | 256-bit  | Encrypts each log entry          |
| Chain Integrity    | HMAC-SHA256         | 256-bit  | Chains entries for tamper evidence|
| License Signing    | Ed25519             | 256-bit  | Signs license JSON               |
| Payload Encryption | AES-256-GCM         | 256-bit  | Encrypts core .so payload        |

## Key Flow

```
1. Application starts → secure_logger::init(fingerprint)
2. Random AES-256 session key + chain key generated
3. Session key encrypted with vendor RSA-2048 public key (embedded in binary)
4. Chain key encrypted with same RSA public key
5. Encrypted keys written to AUDT header
6. For each log event:
   a. Entry = "TIMESTAMP | FP:hash | EVENT | DETAIL"
   b. Chain sig = HMAC-SHA256(prev_chain_sig + entry, chain_key)
   c. Final entry = entry + " | CHAIN:" + hex(chain_sig)
   d. AES-256-GCM encrypt with random 12-byte IV
   e. Append [4-byte len][IV][ciphertext][16-byte tag]
7. On shutdown: OPENSSL_cleanse wipes keys from memory
```

## Configurable Log Path

The audit log path is determined by (in order of priority):
1. `logger_init_path(fingerprint, log_path)` — explicit path via C API / Go bridge
2. `AUDIT_LOG_PATH` environment variable
3. Default: `app_audit.enc` in the same directory as the executable

## C API (license_api.h)

```c
// ── Fingerprint ──
const char* get_fingerprint(void);
const char* get_machine_id(void);
const char* get_cpu_info(void);
const char* get_tpm_ek_hash(void);
int is_tpm_available(void);

// ── License Verification ──
int verify_license_json(const char* license_json);
int check_fingerprint_match(const char* embedded_fp, const char* current_fp);
int verify_license_signature(const char* data, const char* signature, const char* pubkey);

// ── Error Handling ──
const char* get_error_message(void);
void clear_error(void);

// ── Secure Logger ──
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
```

## Go Bridge (aup/internal/license/license.go)

```go
// ── Secure Logger ──
license.LoggerInit(fingerprint)              // Init with default log path
license.LoggerInitWithPath(fingerprint, path) // Init with custom log path
license.LoggerLogEvent(event, detail)
license.LoggerLogStartup()
license.LoggerLogHWValidation(fpHash, match)
license.LoggerLogTamper(reason)
license.LoggerLogTPM(event, success)
license.LoggerLogLicense(action, success)
license.LoggerLogSeal(action, success)
license.LoggerShutdown()
```

## Protected App Audit Events

| Event               | When                                           |
|---------------------|-------------------------------------------------|
| `STARTUP`           | Application launched                            |
| `TPM check OK/FAIL` | TPM availability check                          |
| `LICENSE load OK/FAIL` | License file loaded from disk                |
| `LICENSE verify OK/FAIL` | License signature/fingerprint verified     |
| `HW_VALIDATION MATCH/MISMATCH` | Fingerprint comparison               |
| `TAMPER_DETECTED`   | Any anti-tamper check triggered                 |

## Audit Log Download

The protected app exposes `GET /audit` which serves the `app_audit.enc` file for download. The vendor server's renewal endpoint (`POST /api/license/renew`) accepts this file, decrypts it, and uses the fingerprint to find and renew the matching license.

## Server-Side Audit Processing

The Node.js server handles two formats:
1. **Binary AUDT v2** — C++ `secure_logger` format with `AUDT` magic header
2. **Legacy JSON/line** — fallback for older clients with base64-encoded entries

For binary format, the server:
- Parses the header to extract fingerprint, encrypted AES key, and encrypted chain key
- RSA-OAEP decrypts the AES session key and chain key using the vendor private key
- AES-256-GCM decrypts each log entry
- Extracts fingerprint from entries (regex `FP:([a-f0-9]+)`)
- Looks up matching license and renews it
- Stores decrypted entries in SQLite `audit_logs` table

