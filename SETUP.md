# AUP — Setup & Workflow Guide

New to the repo? Follow these steps exactly to get everything running end-to-end.

## Prerequisites

- **Linux** (uses `/etc/machine-id`, `/proc/cpuinfo`, `/sys/class/dmi/id`)
- **CMake 3.14+**, **GCC** with C++17 support
- **Go 1.21+**
- **Node.js 18+**
- **OpenSSL dev**, **nlohmann_json**, **GTK4 dev headers**, **TSS2 libraries**

## Step 1 — Install Dependencies

```bash
# Ubuntu/Debian
sudo apt install cmake g++ libssl-dev nlohmann-json3-dev libgtk-4-dev libtss2-dev

# Go (if not installed)
# Follow https://go.dev/dl/ or:
sudo snap install go --classic
```

## Step 2 — Build Everything

```bash
# Option A: One-command launcher
./start.sh

# Option B: Build manually

# 2a. Build C++ core (wipe stale cache if rebuilding)
cd client
rm -rf build
cmake -B build
cmake --build build -j$(nproc)
cd ..

# 2b. Copy shared library for Go
cp client/build/libsecure_app_core.so aup/lib/
cp client/include/license_api.h aup/lib/

# 2c. Build Go protected app
cd aup
go build -o bin/protected-app ./cmd/protected-app
cd ..
```

Build outputs:
| Binary | Location | Purpose |
|--------|----------|---------|
| `libsecure_app_core.so` | `client/build/` | Shared lib for Go (also in `aup/lib/`) |
| `get_fingerprint` | `client/build/` | Print hardware fingerprint |
| `keygen` | `client/build/` | Generate Ed25519 keypair |
| `sign_license` | `client/build/` | Sign a license JSON |
| `audit_decrypt` | `client/build/` | Decrypt audit logs |
| `encrypt_core` | `client/build/` | Encrypt the core library |
| `secure_installer` | `client/build/` | CLI installer |
| `secure_installer_gui` | `client/build/` | GTK4 GUI installer |
| `protected-app` | `aup/bin/` | Go protected application |

## Step 3 — Start the Vendor Services

```bash
# Terminal 1: License server
cd vendor/server
npm install
npm start          # → http://localhost:3001

# Terminal 2: Customer portal (optional)
cd vendor/web
npm install
npm run dev        # → http://localhost:3000
```

## Step 4 — Generate Keypair (First Time Only)

```bash
cd client/build
./keygen
# Creates vendor/data/private.pem and vendor/data/public.pem
```

## Step 5 — Get Your Hardware Fingerprint

Pick one method:

```bash
# Option A: C++ tool (most accurate, includes TPM)
./client/build/get_fingerprint

# Option B: Go standalone tool (no C++ lib dependency)
cd aup && go run ./cmd/fingerprint-only

# Option C: Quick shell one-liner (no build needed)
sha256sum /etc/machine-id /sys/class/dmi/id/product_uuid 2>/dev/null | sha256sum | cut -d' ' -f1
```

Save the output — you'll need it in Step 6.

## Step 6 — Generate a License

```bash
# Via API
curl -X POST http://localhost:3001/api/license/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "fingerprint": "<YOUR_FINGERPRINT>",
    "max_users": 10,
    "issued_at": "2026-01-01",
    "expires_at": "2027-01-01"
  }'

# Or via CLI
cd client/build
echo '{"fingerprint":"<YOUR_FINGERPRINT>","expires_at":1795689600,"max_users":10,"customer":"Test"}' > /tmp/license.json
./sign_license /tmp/license.json ../vendor/data/private.pem /tmp/license_signed.json
```

Save the license JSON to `/etc/aup/license.json` or set the `LICENSE_PATH` env var.

## Step 7 — Run the Protected App

```bash
cd aup
export LICENSE_PATH=/tmp/license.json      # default: /etc/aup/license.json
export AUDIT_LOG_PATH=/tmp/app_audit.enc   # default: next to executable

./bin/protected-app
# → Listening on :8443
```

Open **http://localhost:8443** — you should see the dashboard with your license info, fingerprint, and TPM status.

### Web Portal Pages

The system has two web interfaces — a **Vendor Portal** (Next.js on :3000) and a **Customer Dashboard** (Go on :8443):

#### Vendor Portal (http://localhost:3000)

| Page | URL | Auth | Description |
|------|-----|------|-------------|
| Login | `/login` | — | Admin login (username/password) |
| Dashboard | `/dashboard` | Vendor token | 3-tab admin panel: |
| | | | — **License Requests**: Approve/reject customer submissions |
| | | | — **Active Licenses**: View licenses, Copy JSON, View audit logs, Delete |
| | | | — **Business Model**: CRUD pricing plans (name, price in DZD, max users, duration) |
| Request | `/request` | — | Customer: enter fingerprint → finds existing license or opens request form |
| Customer Login | `/customer-login` | — | Customer: log in with fingerprint to retrieve their license |
| My License | `/my-license` | Customer token | Customer: view status, copy/download signed license JSON |

#### Protected App (http://localhost:8443)

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Dark-themed status page showing: customer name, max users, expiry date, TPM availability, hardware fingerprint, license validity badge |
| Audit Download | `/audit` | Downloads the encrypted `app_audit.enc` file (binary AUDT v2 format) |

### What Happens at Startup

```
 1. GetFingerprint()           → C++ reads machine-id + CPU + MAC + TPM EK → SHA256
 2. LoggerInit(fingerprint)    → Generate AES-256 + chain keys → RSA-OAEP encrypt → write AUDT v2 header
 3. LoggerLogStartup()          → Encrypted log: "... | STARTUP | Application launched"
 4. IsTPMAvailable()            → Check TPM
 5. LoggerLogTPM("check",..)   → Encrypted log: "... | TPM | check OK/FAIL"
 6. Load license.json           → Read from LICENSE_PATH or /etc/aup/license.json
 7. LoggerLogLicense("load",.) → Encrypted log: "... | LICENSE | load OK/FAIL"
 8. VerifyLicenseJSON()         → C++ verifies Ed25519 signature
 9. LoggerLogLicense("verify",) → Encrypted log: "... | LICENSE | verify OK/FAIL"
10. CheckFingerprintMatch()     → Compare embedded FP vs current hardware FP
11. LoggerLogHWValidation()     → Encrypted log: "... | HW_VALIDATION | MATCH/MISMATCH fp=..."
12. Check expiry date           → Fatal if expired
13. HTTP server on :8443        → Dashboard at / + audit download at /audit
14. LoggerShutdown() (defer)    → Wipe AES key + chain key from memory
```

If any step fails, the app exits immediately with a fatal log message. The audit log (`app_audit.enc`) is written to `AUDIT_LOG_PATH` or next to the executable.

## Step 8 — Download and Decrypt the Audit Log

```bash
# Download the encrypted audit log from the running app
curl -o /tmp/app_audit.enc http://localhost:8443/audit

# Decrypt it (requires vendor private key)
cd client/build
./audit_decrypt /tmp/app_audit.enc ../../vendor/data/private.pem
```

Output:
```
=== Encrypted Audit Log: /tmp/app_audit.enc ===
  Client Fingerprint: abc123def456...
  [Log version 2: chained HMAC entries]
  [Chain key decrypted successfully (32 bytes)]

  2026-04-25T14:30:01 | FP:abc123def456... | STARTUP | Application launched | CHAIN:a1b2c3...
  2026-04-25T14:30:01 | FP:abc123def456... | TPM | check OK | CHAIN:d4e5f6...
  2026-04-25T14:30:01 | FP:abc123def456... | LICENSE | load OK | CHAIN:...

=== 6 entries decrypted ===
```

## Step 9 — Renew a License via Audit Upload

```bash
curl -X POST http://localhost:3001/api/license/renew \
  -F "audit_file=@/tmp/app_audit.enc"
```

Response:
```json
{ "ok": true, "fingerprint": "abc123...", "new_expires_at": "2027-04-25", "entries_count": 6 }
```

The server:
1. Detects `AUDT` binary magic bytes
2. RSA-OAEP decrypts the AES session key + chain key using `vendor/data/private.pem`
3. AES-256-GCM decrypts each log entry
4. Extracts the fingerprint → finds the matching license in SQLite
5. Extends the license expiry (same duration as original)
6. Stores decrypted entries in the `audit_logs` table

## Step 10 — Review Audit Logs (Admin)

```bash
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:3001/api/license/audit/<fingerprint>
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LICENSE_PATH` | `/etc/aup/license.json` | Path to the license JSON file |
| `AUDIT_LOG_PATH` | `<exe_dir>/app_audit.enc` | Path to the encrypted audit log |
| `PORT` | `8443` | HTTP server port for the protected app |

## Troubleshooting

### `cmake` fails with stale cache
```bash
cd client && rm -rf build && cmake -B build && cmake --build build -j$(nproc)
```

### `go` not found
```bash
sudo snap install go --classic
```

### `libsecure_app_core.so` not found when running
```bash
# Make sure the .so is in aup/lib/ and LD_LIBRARY_PATH is set
export LD_LIBRARY_PATH=$PWD/aup/lib:$LD_LIBRARY_PATH
cd aup && ./bin/protected-app
```

### `next` not found (vendor/web)
```bash
cd vendor/web && npm install
```

### Fingerprint mismatch
- The fingerprint is hardware-bound. If you change hardware or run in a VM, you'll get a different fingerprint and need a new license.

### Audit log decrypt fails
- Make sure you're using the correct `private.pem` (the one matching the public key embedded in `secure_logger.cpp`)
- The `audit_decrypt` tool now supports AUDT v2 (chained entries with encrypted chain key)