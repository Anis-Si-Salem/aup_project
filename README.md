# AUP_Project - On-Premise License Protection System

A comprehensive on-premise software licensing and protection solution combining C++ security core with Go-based protected applications.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AUP_Project System                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────┐     ┌─────────────────────┐                   │
│  │   C++ Security Core │     │   License Server    │                   │
│  │   (client/)         │     │   (vendor/server/)  │                   │
│  │                     │     │                     │                   │
│  │ - TPM Attestation   │     │ - License Generation│                   │
│  │ - Hardware FP      │     │ - Customer Portal    │                   │
│  │ - Anti-RE          │     │ - License Management│                   │
│  │ - Secure Logger    │     │ - Audit Decryption  │                   │
│  │ - License Embed    │     │                     │                   │
│  └─────────┬───────────┘     └─────────┬───────────┘                   │
│            │                           │                               │
│            │ cgo bridge                │                             │
│            ▼                           ▼                               │
│  ┌─────────────────────────────────────────────────────┐               │
│  │          Go Protected App (aup/)                   │               │
│  │                                                     │               │
│  │  - Student Dashboard                               │               │
│  │  - License Verification (via C++)                 │               │
│  │  - Anti-tampering                                  │               │
│  │  - Audit Logging                                   │               │
│  └─────────────────────────────────────────────────────┘               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
aup_project/
├── start.sh                      # One-command launcher (build + run all services)
├── README.md
│
├── client/                        # ── C++ Security Core ──────────────────────
│   ├── CMakeLists.txt             #   Build config (requires OpenSSL, nlohmann_json, GTK4, TSS2)
│   ├── include/                   #   C++ headers
│   │   ├── fingerprint.h          #     Hardware fingerprinting
│   │   ├── tpm_attest.h           #    TPM attestation
│   │   ├── license_api.h          #     C API exported to Go (also copied to aup/lib/)
│   │   └── ...
│   ├── src/                       #   C++ implementation
│   │   ├── fingerprint.cpp        #     Collects machine-id, CPU, MAC, TPM EK hash
│   │   ├── tpm_attest.cpp         #     TPM EK hash extraction
│   │   ├── license_api.cpp        #     C-exported wrapper functions for cgo
│   │   ├── app_core.cpp           #     Core library logic
│   │   └── ...
│   ├── tools/                     #   Standalone CLI tools
│   │   ├── get_fingerprint.cpp    #     Print hardware fingerprint
│   │   ├── keygen.cpp             #     Generate Ed25519 keypair
│   │   ├── sign_license.cpp       #     Sign a license JSON with private key
│   │   ├── encrypt_core.cpp       #     Encrypt the core library
│   │   └── audit_decrypt.cpp       #     Decrypt audit logs
│   └── build/                     #   Compiled output (after cmake --build)
│       ├── libsecure_app_core.so  #     ★ Shared lib — copied to aup/lib/ for Go
│       ├── get_fingerprint        #     CLI: print hardware fingerprint
│       ├── keygen                 #     CLI: generate keypair
│       ├── sign_license           #     CLI: sign license JSON
│       ├── secure_installer       #     CLI installer
│       └── secure_installer_gui   #     GTK4 GUI installer
│
├── aup/                           # ── Go Protected Application ───────────────
│   ├── cmd/
│   │   ├── protected-app/         #   Main app (HTTP dashboard on :8443)
│   │   │   └── main.go           #     Loads license → verifies → serves dashboard
│   │   └── fingerprint-only/      #   Standalone FP tool (no C++ dependency)
│   │       └── main.go           #     Pure Go, reads /etc/machine-id + /proc/cpuinfo
│   ├── internal/
│   │   └── license/               #   cgo bridge to libsecure_app_core.so
│   │       └── license.go        #     GetFingerprint, VerifyLicenseJSON, CheckFingerprintMatch, IsTPMAvailable
│   ├── lib/                       #   Runtime dependency (populated by start.sh or manual cp)
│   │   ├── libsecure_app_core.so  #     ★ Copied from client/build/ — Go links this at runtime
│   │   └── license_api.h          #     ★ Copied from client/include/ — cgo include
│   ├── go.mod                     #   go 1.21
│   └── Makefile
│
└── vendor/                        # ── Node.js Services ───────────────────────
    ├── server/                    #   Express + TypeScript license server (:3001)
    │   ├── src/
    │   │   ├── routes/            #     /api/auth, /api/license, /api/plans
    │   │   ├── middleware/        #     Auth middleware
    │   │   └── utils/             #     Ed25519 signing, crypto helpers
    │   ├── package.json
    │   └── tsconfig.json
    ├── web/                       #   Next.js 16 customer portal (:3000)
    │   ├── src/app/               #     React pages (license mgmt, dashboard)
    │   ├── package.json
    │   └── next.config.mjs
    └── data/                      #   Persistent data
        ├── aup.db                 #     SQLite database (customers, licenses, plans)
        ├── private.pem            #     Ed25519 private key (for signing licenses)
        └── public.pem             #     Ed25519 public key (for verification)
```

### How the Pieces Connect

```
                          ┌─────────────────────┐
                          │  vendor/web :3000   │  Customer portal (Next.js)
                          │  Browse / manage    │
                          └────────┬────────────┘
                                   │ HTTP
                          ┌────────▼────────────┐
                          │ vendor/server :3001  │  License server (Express)
                          │  Sign & issue        │──── private.pem (Ed25519)
                          │  licenses             │
                          └────────┬────────────┘
                                   │ license.json delivered to customer
                          ┌────────▼────────────┐
                          │   aup/ :8443        │  Protected app (Go)
                          │  Verify at startup  │
                          │  Serve dashboard    │
                          └────────┬────────────┘
                                   │ cgo (dlopen)
                          ┌────────▼────────────┐
                          │  libsecure_app_core │  C++ security core (.so)
                          │  TPM, fingerprint,  │
                          │  anti-RE, verify    │
                          └─────────────────────┘
```

1. **Vendor** creates keypair (`keygen`) and signs licenses (`sign_license` or server API)
2. **Customer** runs `get_fingerprint` → sends FP to vendor
3. **Vendor** issues `license.json` bound to that fingerprint
4. **Protected app** starts → loads `license.json` → cgo calls C++ to verify signature + fingerprint match → serves dashboard on :8443

## Building the System

### 1. Build C++ Core (client/)

```bash
cd client
cmake -B build
cmake --build build -j$(nproc)
```

Outputs:
- `build/libsecure_app_core.so` - Shared library for Go integration
- `build/secure_installer` - CLI installer
- `build/secure_installer_gui` - GUI installer

### 2. Get Hardware Fingerprint

```bash
cd client
./build/get_fingerprint
```

### 3. Build Go Protected App (aup/)

```bash
cd aup
go build -o bin/protected-app ./cmd/protected-app
```

Note: Requires C++ shared library at `lib/libsecure_app_core.so`

### 4. Run License Server (vendor/server/)

```bash
cd vendor/server
npm install
npm start
```

## Integration: Option A (C++ as Embedded Library)

### How It Works

The Go protected application uses cgo to call C++ functions from `libsecure_app_core.so`:

```
┌──────────────────────┐      cgo       ┌────────────────────────┐
│   Go Protected App   │ ◀─────────────▶ │ libsecure_app_core.so  │
│                      │                 │                        │
│  1. Call get_fp()    │ ─────────────▶  │ Returns hardware FP   │
│  2. Verify license   │ ─────────────▶  │ Validates license     │
│  3. Check signature  │ ─────────────▶  │ Verifies Ed25519 sig  │
└──────────────────────┘                 └────────────────────────┘
```

### C API (license_api.h)

The C++ library exposes a C-compatible API for Go:

```c
// Get current hardware fingerprint
const char* get_fingerprint(void);

// Verify license against hardware
int verify_license(const char* license_json, const char* fp_hash);

// Check if fingerprint matches
int check_fp_match(const char* embedded_fp, const char* current_fp);

// Verify license signature
int verify_signature(const char* data, const char* signature, const char* pubkey);

// Get error message from last operation
const char* get_error_message(void);
```

### Go cgo Bridge (internal/license/)

```go
package license

// #cgo LDFLAGS: -L${SRCDIR}/../../lib -lsecure_app_core
// #include "license_api.h"
import "C"

func GetFingerprint() (string, error) {
    fp := C.get_fingerprint()
    if fp == nil {
        return "", errors.New(C.GoString(C.get_error_message()))
    }
    return C.GoString(fp), nil
}

func VerifyLicense(licenseJSON, fpHash string) bool {
    return C.verify_license(
        C.CString(licenseJSON),
        C.CString(fpHash),
    ) == 1
}
```

The license package provides:
- `GetFingerprint()` - Get hardware fingerprint from C++
- `VerifyLicenseJSON()` - Verify license JSON is valid
- `CheckFingerprintMatch()` - Match embedded vs current FP
- `IsTPMAvailable()` - Check TPM availability
- `GetError()` - Get last error message

## Fingerprint System

### C++ Fingerprint (Primary)
Collects:
- TPM EK hash (if TPM available)
- Machine ID (`/etc/machine-id`)
- CPU model info
- MAC addresses

### Go Fingerprint (Legacy)
Collects:
- CPU ID from `/proc/cpuinfo`
- Disk serial from `lsblk`
- Board UUID from `/sys/class/dmi/id`

### Unification
The integration uses C++ fingerprinting for stronger hardware binding (TPM-based when available).

## Complete Workflow

See **[SETUP.md](SETUP.md)** for the full step-by-step guide (prerequisites through audit log renewal).

Quick start:

```bash
./start.sh                    # Build everything + start services
./client/build/get_fingerprint  # Get your hardware fingerprint
# Generate a license → place at /etc/aup/license.json
export AUDIT_LOG_PATH=/tmp/app_audit.enc
./aup/bin/protected-app        # → http://localhost:8443
```

## Audit Log Encryption

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Customer   │     │    Vendor    │     │  Protected  │
│  requests    │────▶│  generates   │────▶│    App      │
│  fingerprint │     │  license     │     │  verifies   │
└──────────────┘     └──────────────┘     └──────────────┘
      │                   │                    │
      │ 1. Get FP         │                    │
      ├──────────────────▶│                    │
      │                   │ 2. Sign license   │
      │◀─────────────────┤ with Ed25519      │
      │                   │                    │
      │                   │ 3. Embed in binary │
      │◀──────────────────────────────────────┤
      │                   │                    │
      │                   │    4. Run app      │
      │                   │    Verify at      │
      │                   │    startup        │
```

## Audit Log Encryption

Every event is encrypted and chained for tamper evidence. See [ARCHITECTURE.md](ARCHITECTURE.md) for full details.

### Encryption Stack
| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key wrap | RSA-2048-OAEP-SHA256 | Encrypts per-session AES key with vendor public key |
| Entry encryption | AES-256-GCM (random IV per entry) | Encrypts each log entry |
| Chain integrity | HMAC-SHA256 (chained) | Links entries — tampering with any entry breaks the chain |
| License signing | Ed25519 | Signs license JSON |

### Log File Format (AUDT v2 binary)
```
Header: [AUDT][v2][FP_LEN][fingerprint][ENC_KEY_LEN][encrypted_aes_key][CHAIN_KEY_LEN][encrypted_chain_key]
Entries: [4-byte len][12-byte IV][ciphertext][16-byte GCM tag]
Decrypted: TIMESTAMP | FP:hash | EVENT | DETAIL | CHAIN:hmac_hex
```

## Security Features

### C++ Core
- **TPM Attestation**: Hardware-bound licensing via TPM EK
- **Anti-RE**: Runtime integrity checks
- **Secure Logging**: Encrypted, chained audit logs
- **License Embedding**: Signed license embedded in binary

### Go Application
- **Ed25519 Verification**: Cryptographic license validation
- **Hardware Binding**: Fingerprint matching
- **Canary Traps**: Tamper detection points
- **Distributed Checks**: 10+ verification points
- **Watermarking**: Tamper response on output

## Development

### Running Tests
```bash
# C++ tests
cd client && cmake -B build && cmake --build build

# Go tests
cd aup && go test ./...
```

### Debugging
```bash
# Check fingerprint
./client/build/get_fingerprint

# Run protected app
./aup/bin/protected-app
```

## License

This is a demonstration project for the AUP Hackaton.
