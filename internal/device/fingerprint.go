package device

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// FingerprintData contains device information for fingerprinting
type FingerprintData struct {
	OS           string
	Architecture string
	Hostname     string
	MACAddress   string
	CPUInfo      string
	GoVersion    string
}

// GenerateFingerprint creates a unique device fingerprint
func GenerateFingerprint(deviceID string) string {
	data := collectSystemInfo()
	
	// Combine all data into a single string
	combined := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		deviceID,
		data.OS,
		data.Architecture,
		data.Hostname,
		data.MACAddress,
		data.CPUInfo,
		data.GoVersion,
	)
	
	// Create SHA-256 hash
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash)
}

// collectSystemInfo gathers system information for fingerprinting
func collectSystemInfo() *FingerprintData {
	hostname, _ := os.Hostname()
	
	return &FingerprintData{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Hostname:     hostname,
		MACAddress:   getMACAddress(),
		CPUInfo:      getCPUInfo(),
		GoVersion:    runtime.Version(),
	}
}

// getMACAddress gets the first available MAC address
func getMACAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}

	for _, inter := range interfaces {
		// Skip loopback and invalid interfaces
		if inter.Flags&net.FlagLoopback != 0 {
			continue
		}
		
		if inter.Flags&net.FlagUp == 0 {
			continue
		}
		
		if inter.HardwareAddr != nil && len(inter.HardwareAddr) >= 6 {
			mac := inter.HardwareAddr.String()
			// Skip invalid MAC addresses
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	
	return "00:00:00:00:00:00"
}

// getCPUInfo gets basic CPU information
func getCPUInfo() string {
	return fmt.Sprintf("GOMAXPROCS:%d|NumCPU:%d", runtime.GOMAXPROCS(0), runtime.NumCPU())
}

// ValidateFingerprint verifies if a fingerprint matches the current device
func ValidateFingerprint(deviceID, storedFingerprint string) bool {
	currentFingerprint := GenerateFingerprint(deviceID)
	return strings.EqualFold(currentFingerprint, storedFingerprint)
}

// GetSystemInfo returns current system information in a structured format
func GetSystemInfo() map[string]string {
	hostname, _ := os.Hostname()
	data := collectSystemInfo()
	
	return map[string]string{
		"os":            data.OS,
		"architecture":  data.Architecture,
		"hostname":      hostname,
		"num_cpu":       fmt.Sprintf("%d", runtime.NumCPU()),
		"gomaxprocs":    fmt.Sprintf("%d", runtime.GOMAXPROCS(0)),
		"go_version":    data.GoVersion,
		"mac_address":   data.MACAddress,
		"fingerprint":   GenerateFingerprint("system"),
	}
}

// GetDetailedSystemInfo returns detailed system information
func GetDetailedSystemInfo() map[string]interface{} {
	data := collectSystemInfo()
	
	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Get network interfaces
	interfaces, _ := net.Interfaces()
	var networkInterfaces []map[string]interface{}
	
	for _, inter := range interfaces {
		interfaceInfo := map[string]interface{}{
			"name":  inter.Name,
			"flags": inter.Flags.String(),
		}
		
		if inter.HardwareAddr != nil {
			interfaceInfo["mac_address"] = inter.HardwareAddr.String()
		}
		
		// Get IP addresses
		addrs, err := inter.Addrs()
		if err == nil && len(addrs) > 0 {
			var ipAddresses []string
			for _, addr := range addrs {
				ipAddresses = append(ipAddresses, addr.String())
			}
			interfaceInfo["addresses"] = ipAddresses
		}
		
		networkInterfaces = append(networkInterfaces, interfaceInfo)
	}
	
	return map[string]interface{}{
		"system": map[string]interface{}{
			"os":           data.OS,
			"architecture": data.Architecture,
			"hostname":     data.Hostname,
			"go_version":   data.GoVersion,
		},
		"cpu": map[string]interface{}{
			"num_cpu":       runtime.NumCPU(),
			"gomaxprocs":    runtime.GOMAXPROCS(0),
			"cpu_info":      data.CPUInfo,
		},
		"memory": map[string]interface{}{
			"alloc":         memStats.Alloc,
			"total_alloc":   memStats.TotalAlloc,
			"sys":           memStats.Sys,
			"num_gc":        memStats.NumGC,
			"gc_cpu_fraction": memStats.GCCPUFraction,
		},
		"network": map[string]interface{}{
			"primary_mac":  data.MACAddress,
			"interfaces":   networkInterfaces,
		},
		"fingerprint": GenerateFingerprint("detailed-system"),
	}
}

// CompareFingerprints compares two fingerprints and returns similarity percentage
func CompareFingerprints(fp1, fp2 string) float64 {
	if fp1 == fp2 {
		return 100.0
	}
	
	if len(fp1) != len(fp2) {
		return 0.0
	}
	
	matches := 0
	for i := range fp1 {
		if fp1[i] == fp2[i] {
			matches++
		}
	}
	
	return float64(matches) / float64(len(fp1)) * 100.0
}

// GenerateFingerprintWithSalt creates a salted fingerprint for enhanced security
func GenerateFingerprintWithSalt(deviceID, salt string) string {
	data := collectSystemInfo()
	
	combined := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		deviceID,
		salt,
		data.OS,
		data.Architecture,
		data.Hostname,
		data.MACAddress,
		data.CPUInfo,
		data.GoVersion,
		fmt.Sprintf("%d", os.Getpid()), // Add process ID for uniqueness
	)
	
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash)
}
