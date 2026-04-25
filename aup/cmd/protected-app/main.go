package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aup/aup/internal/license"
)

type License struct {
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   int64  `json:"expires_at"`
	MaxUsers   int    `json:"max_users"`
	Customer   string `json:"customer"`
	Signature  string `json:"signature"`
}

type PageData struct {
	Title       string
	License     *License
	Fingerprint string
	TPMAvailable bool
	Error       string
}

var appLicense *License

func main() {
	log.Println("AUP Protected Application starting...")

	licensePath := "/etc/aup/license.json"
	if envPath := os.Getenv("LICENSE_PATH"); envPath != "" {
		licensePath = envPath
	}

	fp, err := license.GetFingerprint()
	if err != nil {
		log.Printf("WARNING: Could not get fingerprint: %v", err)
		fp = "unknown"
	}
	log.Printf("Hardware Fingerprint: %s", fp)

	license.LoggerInit(fp)
	defer license.LoggerShutdown()
	license.LoggerLogStartup()

	tpmAvail := license.IsTPMAvailable()
	log.Printf("TPM Available: %v", tpmAvail)
	license.LoggerLogTPM("check", tpmAvail)

	licenseData, err := os.ReadFile(licensePath)
	if err != nil {
		license.LoggerLogLicense("load", false)
		log.Fatalf("Failed to load license from %s: %v", licensePath, err)
	}
	license.LoggerLogLicense("load", true)

	if err := json.Unmarshal(licenseData, &appLicense); err != nil {
		license.LoggerLogLicense("parse", false)
		log.Fatalf("Failed to parse license: %v", err)
	}

	if !license.VerifyLicenseJSON(string(licenseData)) {
		license.LoggerLogLicense("verify", false)
		log.Fatalf("License verification failed: %s", license.GetError())
	}
	license.LoggerLogLicense("verify", true)

	if !license.CheckFingerprintMatch(appLicense.Fingerprint, fp) {
		license.LoggerLogHWValidation(fp, false)
		license.LoggerLogTamper("fingerprint_mismatch")
		log.Fatalf("FINGERPRINT MISMATCH! License bound to: %s, current: %s",
			appLicense.Fingerprint, fp)
	}
	license.LoggerLogHWValidation(fp, true)

	if appLicense.ExpiresAt > 0 && appLicense.ExpiresAt < time.Now().Unix() {
		license.LoggerLogLicense("expired", false)
		log.Fatalf("License expired on %s", time.Unix(appLicense.ExpiresAt, 0))
	}

	log.Printf("License valid for customer: %s (max %d users, expires %s)",
		appLicense.Customer, appLicense.MaxUsers,
		time.Unix(appLicense.ExpiresAt, 0).Format("2006-01-02"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/audit", handleAuditDownload)

	addr := ":8443"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	fp, _ := license.GetFingerprint()
	tpmAvail := license.IsTPMAvailable()

	data := PageData{
		Title:        "AUP Protected Dashboard",
		License:      appLicense,
		Fingerprint: fp,
		TPMAvailable: tpmAvail,
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>%s</title>
	<style>
		body { font-family: system-ui, -apple-system, sans-serif; background: #111; color: #fff; min-height: 100vh; margin: 0; }
		.container { max-width: 800px; margin: 0 auto; padding: 2rem; }
		h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
		.card { background: #222; border: 1px solid #333; border-radius: 0.5rem; padding: 1.25rem; margin-bottom: 1rem; }
		.card-title { font-size: 0.7rem; text-transform: uppercase; color: #888; margin-bottom: 0.5rem; }
		.card-value { font-size: 1.25rem; font-weight: 600; }
		.mono { font-family: monospace; font-size: 0.8rem; word-break: break-all; color: #4f4; }
		.badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; }
		.badge-ok { background: #252; color: #4f4; border: 1px solid #4f4; }
		.badge-warn { background: #420; color: #fa4; border: 1px solid #fa4; }
		.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
	</style>
</head>
<body>
	<div class="container">
		<h1>AUP Protected Application</h1>
		
		<div class="grid">
			<div class="card">
				<div class="card-title">Customer</div>
				<div class="card-value">%s</div>
			</div>
			<div class="card">
				<div class="card-title">Max Users</div>
				<div class="card-value">%d</div>
			</div>
			<div class="card">
				<div class="card-title">Expires</div>
				<div class="card-value">%s</div>
			</div>
			<div class="card">
				<div class="card-title">TPM Available</div>
				<div class="card-value">%s</div>
			</div>
		</div>

		<div class="card">
			<div class="card-title">Hardware Fingerprint</div>
			<div class="mono">%s</div>
		</div>

		<div class="card">
			<div class="card-title">License Status</div>
			<span class="badge badge-ok">VALID</span>
		</div>
	</div>
</body>
</html>`, 
		data.Title,
		data.License.Customer,
		data.License.MaxUsers,
		time.Unix(data.License.ExpiresAt, 0).Format("2006-01-02"),
		map[bool]string{true: "Yes", false: "No"}[data.TPMAvailable],
		data.Fingerprint,
	)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleAuditDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		http.Error(w, "Cannot determine executable path", http.StatusInternalServerError)
		return
	}
	auditPath := filepath.Join(filepath.Dir(exe), "app_audit.enc")

	if envPath := os.Getenv("AUDIT_LOG_PATH"); envPath != "" {
		auditPath = envPath
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		http.Error(w, "Audit log not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=app_audit.enc")
	w.Write(data)
}