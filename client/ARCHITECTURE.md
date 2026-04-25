# On-Premise Software Licensing & DRM Suite

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ONLINE PC (Website)                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐   │
│  │ License     │    │ Log         │    │ Ed25519 Key Pair    │   │
│  │ Generator   │    │ Analyzer    │    │ (Vendor Private)    │   │
│  └──────┬──────┘    └──────┬──────┘    └──────────┬──────────┘   │
└─────────┼───────────────────┼─────────────────────┼──────────────┘
          │                   │                     │
          │ download         │ upload              │
          ▼                   ▼                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      OFFLINE PC (Installation)                        │
│  ┌─────────────────┐   ┌────────────────┐   ┌────────────────┐  │
│  │ secure_installer │   │ secure_app    │   │ app_audit.enc │  │
│  │ (CLI or GUI)    │──▶│ (protected)  │──▶│ (logs)        │  │
│  └────────┬────────┘   └────────┬───────┘   └───────┬────────┘   │
│           │                     │                   │           │
│           │ re-encrypt          │ verify +          │ encrypt   │
│           │ + embed             │ run               │ with RSA │
└───────────┼─────────────────────┼───────────────────┼───────────┘
            │                     │                   │
            ▼                     ▼                   ▼
       LICENSE               TPM              VENDOR
        .JSON              BOUND               ONLY
```

---

## Phase 1: Getting Fingerprint (Offline PC)

### Command
```bash
./secure_installer
# or
./secure_installer_gui
```

### Output
```
╔══════════════════════════════════════════════╗
║     ON-PREMISE SECURITY INSTALLER            ║
╚══════════════════════════════════════════════╝

  ━━━ Step 1: Hardware Fingerprint ━━━━━━━━━━━━

  TPM/vTPM:    DETECTED
  TPM EK Hash: a1b2c3d4e5f6789012345678901234567890123456789012345678901234
  → License will be bound to this specific TPM.

  ┌──────────────────────────────────────────────────┐
  │  FINGERPRINT                                    │
  │  a1b2c3d4e5f6789012345678901234567890123456789012345678901234 │
  │  Send this hash to your vendor to receive a    │
  │  signed license file.                          │
  └──────────────────────────────────────────────────┘
```

### Key Points
- **TPM is MANDATORY** — installation refuses if no TPM
- Fingerprint = TPM EK hash (unique per TPM chip)
- Non-TPM machines cannot use this software

---

## Phase 2: Getting License (Website)

### User Input on Website
| Field | Example |
|-------|---------|
| Fingerprint | `a1b2c3d4e5f6789...` (from installer) |
| Max Users | `100` |
| Duration (days) | `365` |
| Private Key | `vendor_privkey.pem` |

### Website Processing
```typescript
# 1. Create license JSON (unsigned)
license = {
    "fingerprint": user_fingerprint,  # TPM EK hash
    "issued_at": "2026-04-25T00:00:00",
    "expires_at": "2027-04-25T00:00:00",
    "max_users": 100
}

# 2. Sign with vendor's Ed25519 private key
signature = ed25519_sign(private_key, json.dumps(license, sort_keys=True))

# 3. Add signature to JSON
license["signature"] = base64.b64encode(signature).decode()
```

### Download (2 files)
1. **license.json**
```json
{
  "fingerprint": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
  "issued_at": "2026-04-25T00:00:00",
  "expires_at": "2027-04-25T00:00:00",
  "max_users": 100,
  "signature": "BASE64_ED25519_SIGNATURE_BYTES"
}
```

2. **pubkey.pem**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqx1...
-----END PUBLIC KEY-----
```

---

## Phase 3: Installation (Offline PC)

### User Input
```bash
./secure_installer license.json pubkey.pem
# or
./secure_installer_gui  # then select files via dialog
```

### What's Created

| File | Description | Contents |
|------|-------------|-----------|
| `/usr/local/bin/secure_app` | Installed binary | App code + **embedded license** (4096 bytes) |
| `/usr/local/bin/app_core.enc` | Encrypted payload | AES-256-GCM encrypted `libsecure_app_core.so` |
| `/usr/local/bin/app_core.enc.key.tss` | TPM-sealed key | AES key sealed to THIS TPM |
| `/usr/local/bin/app_audit.enc` | Audit log | (created at runtime) |

### Installation Process
```
1. Read license.json + pubkey.pem
2. Verify Ed25519 signature
3. Verify fingerprint matches THIS machine's TPM EK hash
4. Generate NEW random AES-256 key
5. Re-encrypt payload with new key
6. Seal new key to TPM (if available) → app_core.enc.key.tss
7. Embed license + signature into binary → secure_app
8. Write encrypted payload → app_core.enc
```

---

## Phase 4: Running the Application

### Startup Flow
```
secure_app starts:
┌─────────────────────────────────────────────────────────────┐
│ 1. ANTI-RE CHECKS                                           │
│    • Check TracerPid in /proc/self/status                    │
│    • Check LD_PRELOAD, Frida in /proc/self/maps            │
│    • Compute .text segment checksum                      │
│    → If any fail: _exit(137)                              │
├─────────────────────────────────────────────────────────────┤
│ 2. TPM VERIFICATION                                        │
│    • Verify TPM exists (/dev/tpm0)                         │
│    • Get current TPM EK hash                              │
│    → If no TPM: _exit(137)                                │
├──────────────────────────────────────────────��──────────────┤
│ 3. LICENSE VERIFICATION                                   │
│    • Read embedded license from binary                     │
│    • Verify SHA256 struct integrity                      │
│    • Verify Ed25519 signature                           │
│    • Verify TPM EK hash matches embedded                │
│    → If any fail: _exit(137)                            │
├─────────────────────────────────────────────────────────────┤
│ 4. EXPIRY CHECK                                            │
│    • Check expiry_timestamp vs current time              │
│    → If expired: _exit(137)                               │
├─────────────────────────────────────────────────────────────┤
│ 5. START BACKGROUND MONITOR                                │
│    • Set license expiry in config                       │
│    • Start thread that every 2-5 sec:                    │
│      - Checks TracerPid                                 │
│      - Checks breakpoints                               │
│      - Checks .text checksum                           │
│      - Checks expiry (auto-terminate if expired)         │
│      - Increments heartbeat                             │
├─────────────────────────────────────────────────────────────┤
│ 6. DECRYPT PAYLOAD                                         │
│    • Unseal AES key from .key.tss using TPM                │
│    • Decrypt app_core.enc with AES key                   │
│    • Load into memory via memfd_create                  │
│    • Apply F_SEAL_* to prevent modification           │
├─────────────────────────────────────────────────────────────┤
│ 7. INITIALIZE LOGGING                                      │
│    • Generate random session AES key                  │
│    • Encrypt with vendor's RSA public key              │
│    • Write header to app_audit.enc                       │
│    • Log STARTUP event                                   │
├─────────────────────────────────────────────────────────────┤
│ 8. RUN APP_CORE                                            │
│    • dlopen the decrypted shared library               │
│    • Call app_main()                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 5: License Renewal

### User Steps
```bash
# 1. Get new license from website
cp new_license.json /tmp/
cp new_pubkey.pem /tmp/

# 2. Reinstall (patches binary with new license)
/usr/local/bin/secure_installer /tmp/new_license.json /tmp/new_pubkey.pem
```

### What's Updated
| Field | Old → New |
|-------|-----------|
| `expiry_timestamp` | Old date → New date |
| `ed25519_signature` | Old sig → New sig |
| `canonical_json` | Old JSON → New JSON |
| `struct_integrity` | Old hash → New hash |

---

## Phase 6: Audit Log Submission

### User Action
1. App creates `/usr/local/bin/app_audit.enc` (encrypted at runtime)
2. User uploads this file to website

### Website Processing (audit_decrypt)
```bash
./audit_decrypt app_audit.enc vendor_privkey.pem
```

### Output
```
=== Encrypted Audit Log: app_audit.enc ===
  Client Fingerprint: a1b2c3d4...

  2026-04-25T14:32:01 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | STARTUP | Application launched
  2026-04-25T14:32:02 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | HW_VALIDATION | MATCH
  2026-04-25T14:32:03 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | TPM | unseal_key OK
  2026-04-25T14:32:03 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | LICENSE | launch OK
  2026-04-25T14:33:15 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | TAMPER_DETECTED | TracerPid detected

=== 5 entries decrypted ===
```

---

## ⛔ ATTACK VULNERABILITY: Fake Logs

### The Problem
```
ATTACKER CAN DO:
─────────────────────────────────────────────────────
1. Copy license.json + pubkey.pem from valid user
2. Run FAKE app on DIFFERENT PC (no TPM needed!)
3. Generate FAKE logs: "STARTUP OK", "All good"
4. Encrypt with PUBLIC KEY → encrypts fine!
5. Submit to vendor
6. Vendor decrypts → "looks legitimate" ❌
```

Anyone with the **public key** can encrypt fake logs!

### The Fix: Fingerprint + Chain-Bound Log Entries

Each log entry NOW includes:
1. **Fingerprint** (from license, stored in vendor DB)
2. **HMAC Chain** (prevents modification)

```
LOG FORMAT (before):
[TIMESTAMP] | [EVENT] | [DETAIL]

LOG FORMAT (after):  
[TIMESTAMP] | FP:[FINGERPRINT] | [EVENT] | CHAIN:[HMAC]

Example:
2026-04-25T14:32:01 | FP:a1b2c3d4e5f678901234567890123456789012345678901234 | STARTUP | Application launched | CHAIN:abc123...
```

**Chain Formula:**
```
HMAC-SHA256(chain_key, previous_signature + current_entry_data)
```

Each entry's CHAIN depends on all previous entries - can't add/modify/delete!

**Vendor Verification Process:**
```
1. Decrypt log entry with private key
2. Parse: [timestamp] | FP:xxxx | [event] | CHAIN:yyyy
3. Verify HMAC chain is valid
4. Extract FP from entry: "a1b2c3..."
5. Check database: SELECT * FROM licenses WHERE fingerprint = 'FP'
6. If valid license + non-expired → ACCEPT ✅
7. If not found / expired → REJECT ❌
```

**Defense Against:**
- ❌ Fake logs with random fingerprint → DB check FAILS
- ❌ Copy license from other machine → Works but...
- ❌ ...can't generate valid HMAC chain without chain key
- ❌ Delete/modify entries → Chain breaks

---

## Security Features

### 1. TPM-Based Hardware Binding
- **What**: License bound to TPM EK hash
- **Why**: TPM is hardware — cannot be cloned
- **How**: Fingerprint = TPM EK hash, verified at runtime

### 2. Ed25519 Signature Verification
- **What**: License cryptographically signed
- **Why**: Only vendor can issue licenses
- **How**: Ed25519 signature in license.json verified against embedded public key

### 3. Embedded License Integrity
- **What**: SHA256 hash of embedded struct
- **Why**: Detect tampering with binary
- **How**: `struct_integrity` field in embedded struct verified at runtime

### 4. Encrypted Payload
- **What**: App code encrypted with AES-256-GCM
- **Why**: Can't run without license + TPM key
- **How**: Key sealed to TPM, decrypted at runtime only

### 5. Runtime TPM Verification
- **What**: Re-verify TPM matches license
- **Why**: Prevent moving to different hardware
- **How**: Compare current TPM EK hash with embedded

### 6. Periodic Expiry Check
- **What**: Background thread checks every 2-5 seconds
- **Why**: Auto-terminate when license expires
- **How**: If `time() >= expiry_timestamp`, `_exit(137)`

### 7. Anti-Debugging
- **What**: Checks for tracer, breakpoints, Frida
- **Why**: Detect debugging/hooking attempts
- **How**: Check /proc/self/status, /proc/self/maps, .text checksum

### 8. Encrypted Audit Logs
- **What**: All events logged, encrypted with RSA
- **Why**: Evidence for license disputes
- **How**: Hybrid encryption — session key sealed with vendor public key

---

## Why License Transfer Fails

| Attempt | Why It Fails |
|--------|--------------|
| Copy installed app to another PC | TPM mismatch — app checks TPM EK hash |
| Copy license.json to another PC | Different TPM = different fingerprint |
| Extract and copy `.enc.key.tss` | TPM unseal only works on SAME TPM |
| Modify binary | SHA256 integrity check fails |
| Clock manipulation | Expiry is Unix timestamp, checked against current time |

---

## File Locations After Installation

```
/usr/local/bin/
├── secure_app              # Main binary with embedded license
├── secure_app_gui        # GUI version
├── app_core.enc          # Encrypted app payload
├── app_core.enc.key.tss  # TPM-sealed AES key
├── app_core.enc.key.bin # Fallback key (if no TPM)
└── app_audit.enc        # Created at runtime
```

---

## Vendor Tools

| Tool | Purpose |
|------|---------|
| `keygen` | Generate Ed25519 keypair |
| `sign_license` | Sign license.json with private key |
| `encrypt_core` | Encrypt app payload with AES key |
| `audit_decrypt` | Decrypt audit logs with private key |

### Workflow
```bash
# 1. Generate keys (once)
./keygen → vendor_privkey.pem + vendor_pubkey.pem

# 2. Sign license
./sign_license license.json vendor_privkey.pem → license.json (with signature)

# 3. Encrypt payload
./encrypt_core libsecure_app_core.so app_core.enc app_core.key → app_core.enc + app_core.key

# 4. Decrypt logs (for analysis)
./audit_decrypt app_audit.enc vendor_privkey.pem
```

---

## Security Summary

| Layer | Protection |
|-------|------------|
| TPM Required | No installation without TPM |
| TPM EK Binding | License tied to specific chip |
| Ed25519 Sig | Only vendor can issue licenses |
| AES-256-GCM | Payload encrypted at rest |
| TPM-Sealed Key | AES key unusable on other TPMs |
| Runtime Verification | App refuses wrong hardware |
| Anti-Debug | Detects Frida, GDB, breakpoints |
| Encrypted Logs | Only vendor can review |
| Expiry Enforcement | Auto-terminates on expiration |

---

## Limitations / Known Issues

1. **No offline renewal** — must reinstall to update license
2. **TPM required** — won't work on machines without TPM
3. **Single machine per license** — one license = one TPM
4. **No trial mode** — installation always requires license
5. **Audit logs one-way** — user must manually transport file to website