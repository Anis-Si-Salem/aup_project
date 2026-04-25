package license

// #cgo CXXFLAGS: -std=c++17
// #cgo LDFLAGS: -L${SRCDIR}/../../lib -lsecure_app_core -lstdc++
// #include "license_api.h"
import "C"

import (
	"errors"
	"unsafe"
)

var lastError string

func GetFingerprint() (string, error) {
	lastError = ""
	fp := C.get_fingerprint()
	if fp == nil {
		lastError = C.GoString(C.get_error_message())
		return "", errors.New(lastError)
	}
	return C.GoString(fp), nil
}

func GetMachineID() (string, error) {
	lastError = ""
	mid := C.get_machine_id()
	if mid == nil {
		lastError = C.GoString(C.get_error_message())
		return "", errors.New(lastError)
	}
	return C.GoString(mid), nil
}

func GetCPUInfo() (string, error) {
	lastError = ""
	cpu := C.get_cpu_info()
	if cpu == nil {
		lastError = C.GoString(C.get_error_message())
		return "", errors.New(lastError)
	}
	return C.GoString(cpu), nil
}

func GetTPMEKHash() (string, error) {
	lastError = ""
	ek := C.get_tpm_ek_hash()
	if ek == nil {
		lastError = C.GoString(C.get_error_message())
		return "", errors.New(lastError)
	}
	return C.GoString(ek), nil
}

func IsTPMAvailable() bool {
	return C.is_tpm_available() == 1
}

func VerifyLicenseJSON(licenseJSON string) bool {
	lastError = ""
	c_license := C.CString(licenseJSON)
	defer C.free(unsafe.Pointer(c_license))
	
	result := C.verify_license_json(c_license)
	if result == 0 {
		lastError = C.GoString(C.get_error_message())
		return false
	}
	return true
}

func CheckFingerprintMatch(embeddedFP, currentFP string) bool {
	lastError = ""
	c_emb := C.CString(embeddedFP)
	c_cur := C.CString(currentFP)
	defer func() {
		C.free(unsafe.Pointer(c_emb))
		C.free(unsafe.Pointer(c_cur))
	}()
	
	return C.check_fingerprint_match(c_emb, c_cur) == 1
}

func VerifyLicenseSignature(data, signature, pubkey string) bool {
	lastError = ""
	c_data := C.CString(data)
	c_sig := C.CString(signature)
	c_key := C.CString(pubkey)
	defer func() {
		C.free(unsafe.Pointer(c_data))
		C.free(unsafe.Pointer(c_sig))
		C.free(unsafe.Pointer(c_key))
	}()
	
	return C.verify_license_signature(c_data, c_sig, c_key) == 1
}

func GetError() string {
	return lastError
}

// ── Secure Logger ──

func LoggerInit(fingerprint string) {
	c_fp := C.CString(fingerprint)
	defer C.free(unsafe.Pointer(c_fp))
	C.logger_init(c_fp)
}

func LoggerInitWithPath(fingerprint string, logPath string) {
	c_fp := C.CString(fingerprint)
	c_path := C.CString(logPath)
	defer func() {
		C.free(unsafe.Pointer(c_fp))
		C.free(unsafe.Pointer(c_path))
	}()
	C.logger_init_path(c_fp, c_path)
}

func LoggerLogEvent(event string, detail string) {
	c_evt := C.CString(event)
	c_det := C.CString(detail)
	defer func() {
		C.free(unsafe.Pointer(c_evt))
		C.free(unsafe.Pointer(c_det))
	}()
	C.logger_log_event(c_evt, c_det)
}

func LoggerLogStartup() {
	C.logger_log_startup()
}

func LoggerLogHWValidation(fpHash string, match bool) {
	c_fp := C.CString(fpHash)
	defer C.free(unsafe.Pointer(c_fp))
	var m C.int
	if match {
		m = 1
	}
	C.logger_log_hw_validation(c_fp, m)
}

func LoggerLogTamper(reason string) {
	c_r := C.CString(reason)
	defer C.free(unsafe.Pointer(c_r))
	C.logger_log_tamper(c_r)
}

func LoggerLogTPM(event string, success bool) {
	c_e := C.CString(event)
	defer C.free(unsafe.Pointer(c_e))
	var s C.int
	if success {
		s = 1
	}
	C.logger_log_tpm(c_e, s)
}

func LoggerLogLicense(action string, success bool) {
	c_a := C.CString(action)
	defer C.free(unsafe.Pointer(c_a))
	var s C.int
	if success {
		s = 1
	}
	C.logger_log_license(c_a, s)
}

func LoggerLogSeal(action string, success bool) {
	c_a := C.CString(action)
	defer C.free(unsafe.Pointer(c_a))
	var s C.int
	if success {
		s = 1
	}
	C.logger_log_seal(c_a, s)
}

func LoggerShutdown() {
	C.logger_shutdown()
}