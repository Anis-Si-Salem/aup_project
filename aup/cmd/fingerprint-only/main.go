package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

func main() {
	machineID := readFile("/etc/machine-id")
	productUUID := readFile("/sys/class/dmi/id/product_uuid")
	cpuModel := readCPUInfo()

	fp := sha256.Sum256([]byte(strings.Join([]string{
		machineID, productUUID, cpuModel,
	}, "|")))
	fmt.Printf("Fingerprint: %x\n", fp)
	fmt.Printf("  Machine ID:   %s\n", machineID)
	fmt.Printf("  Product UUID: %s\n", productUUID)
	fmt.Printf("  CPU:          %s\n", cpuModel)
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readCPUInfo() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}