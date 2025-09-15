package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/hashmi846003/P.K.I/internal/certificate"
	"github.com/hashmi846003/P.K.I/internal/config"
	"github.com/hashmi846003/P.K.I/internal/database"
	"github.com/hashmi846003/P.K.I/internal/device"
	"github.com/hashmi846003/P.K.I/internal/models"
	"github.com/hashmi846003/P.K.I/internal/tpm"
)

type Server struct {
	config      *config.Config
	db          *database.DB
	httpServer  *http.Server
	certManager *certificate.Manager
	renewalMgr  *certificate.RenewalManager
	tpmManager  *tpm.TPMManager
}

func NewServer(cfg *config.Config, db *database.DB) (*Server, error) {
	certManager := certificate.NewManager(db)
	renewalManager := certificate.NewRenewalManager(certManager)
	tpmManager := tpm.GetTPMManager()

	s := &Server{
		config:      cfg,
		db:          db,
		certManager: certManager,
		renewalMgr:  renewalManager,
		tpmManager:  tpmManager,
	}
	s.setupRoutes()
	return s, nil
}

func (s *Server) setupRoutes() {
	r := mux.NewRouter()

	r.Use(s.corsMiddleware)
	r.Use(s.loggingMiddleware)
	r.Use(s.recoveryMiddleware)

	// Health endpoints
	r.HandleFunc("/health", s.healthCheckHandler).Methods("GET")
	r.HandleFunc("/info", s.systemInfoHandler).Methods("GET")
	r.HandleFunc("/stats", s.systemStatsHandler).Methods("GET")

	// Certificate Authority endpoints
	r.HandleFunc("/ca", s.createCAHandler).Methods("POST")
	r.HandleFunc("/ca/{id:[0-9]+}", s.getCAHandler).Methods("GET")
	r.HandleFunc("/ca", s.listCAsHandler).Methods("GET")
	r.HandleFunc("/ca/{id:[0-9]+}", s.deleteCAHandler).Methods("DELETE")

	// Device endpoints
	r.HandleFunc("/devices", s.registerDeviceHandler).Methods("POST")
	r.HandleFunc("/devices/{deviceId}", s.getDeviceHandler).Methods("GET")
	r.HandleFunc("/devices/{deviceId}/fingerprint", s.updateFingerprintHandler).Methods("PUT")
	r.HandleFunc("/devices", s.listDevicesHandler).Methods("GET")

	// User endpoints
	r.HandleFunc("/users", s.createUserHandler).Methods("POST")
	r.HandleFunc("/users/{id:[0-9]+}", s.getUserHandler).Methods("GET")
	r.HandleFunc("/users", s.listUsersHandler).Methods("GET")

	// Certificate endpoints
	r.HandleFunc("/certificates", s.issueCertificateHandler).Methods("POST")
	r.HandleFunc("/certificates/{serialNumber}", s.getCertificateHandler).Methods("GET")
	r.HandleFunc("/certificates/device/{deviceId}", s.listDeviceCertificatesHandler).Methods("GET")
	r.HandleFunc("/certificates/user/{userId:[0-9]+}", s.listUserCertificatesHandler).Methods("GET")
	r.HandleFunc("/certificates/ca/{caId:[0-9]+}", s.listCACertificatesHandler).Methods("GET")
	r.HandleFunc("/certificates/{serialNumber}/revoke", s.revokeCertificateHandler).Methods("POST")
	r.HandleFunc("/certificates/{serialNumber}/validate", s.validateCertificateHandler).Methods("GET")
	r.HandleFunc("/certificates/stats", s.getCertificateStatsHandler).Methods("GET")

	// Certificate renewal endpoints
	r.HandleFunc("/certificates/{serialNumber}/renew", s.renewCertificateHandler).Methods("POST")
	r.HandleFunc("/certificates/expiring", s.listExpiringCertificatesHandler).Methods("GET")
	r.HandleFunc("/certificates/auto-renew", s.autoRenewHandler).Methods("POST")
	r.HandleFunc("/certificates/{serialNumber}/renewal-info", s.getRenewalInfoHandler).Methods("GET")
	r.HandleFunc("/certificates/renewal-stats", s.getRenewalStatsHandler).Methods("GET")
	r.HandleFunc("/certificates/bulk-renew", s.bulkRenewHandler).Methods("POST")

	// TPM endpoints
	r.HandleFunc("/tpm/info", s.tpmInfoHandler).Methods("GET")
	r.HandleFunc("/tpm/generate-key", s.tpmGenerateKeyHandler).Methods("POST")
	r.HandleFunc("/tpm/attest/{deviceId}", s.tpmAttestHandler).Methods("POST")
	r.HandleFunc("/tpm/encrypt", s.tpmEncryptHandler).Methods("POST")
	r.HandleFunc("/tpm/decrypt", s.tpmDecryptHandler).Methods("POST")
	r.HandleFunc("/tpm/quote", s.tpmQuoteHandler).Methods("POST")
	r.HandleFunc("/tpm/metrics", s.tpmMetricsHandler).Methods("GET")

	// Database endpoints
	r.HandleFunc("/database/stats", s.databaseStatsHandler).Methods("GET")
	r.HandleFunc("/database/health", s.databaseHealthHandler).Methods("GET")

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.ServerPort),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

func (s *Server) Start() error {
	log.Printf("Starting server on port %d", s.config.ServerPort)
	if s.config.TLSEnabled {
		return s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

// Middlewares

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)
		log.Printf("📡 %s %s %d %v", r.Method, r.RequestURI, wrapped.statusCode, duration)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("🚨 Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Helper JSON writers

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to write JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func writeJSONCreated(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to write JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Health Handlers

func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":      "healthy",
		"timestamp":   time.Now().Format(time.RFC3339),
		"version":     "1.0.0",
		"database":    "connected",
		"server_port": s.config.ServerPort,
	}
	if err := s.db.HealthCheck(); err != nil {
		health["status"] = "unhealthy"
		health["database"] = "error: " + err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if s.tpmManager.IsTPMAvailable() {
		health["tpm"] = "available"
	} else {
		health["tpm"] = "simulation_mode"
	}
	writeJSON(w, health)
}

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	sysInfo := device.GetDetailedSystemInfo()
	sysInfo["tpm"] = s.tpmManager.GetTPMInfo()
	sysInfo["server"] = map[string]interface{}{
		"port":        s.config.ServerPort,
		"tls_enabled": s.config.TLSEnabled,
		"log_level":   s.config.LogLevel,
	}
	writeJSON(w, sysInfo)
}

func (s *Server) systemStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"database": s.db.GetStats(),
		"tpm":      s.tpmManager.GetTPMMetrics(),
		"uptime":   time.Since(time.Now().Truncate(time.Hour)).String(),
	}
	if certStats, err := s.certManager.GetCertificateStats(); err == nil {
		stats["certificates"] = certStats
	}
	writeJSON(w, stats)
}

// CA Handlers

func (s *Server) createCAHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "Invalid CA name", http.StatusBadRequest)
		return
	}
	ca, err := s.certManager.CreateCA(req.Name)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create CA: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONCreated(w, ca.ToJSON())
}

func (s *Server) getCAHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}
	ca, err := s.certManager.GetCAByIDExported(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, ca.ToJSON())
}

func (s *Server) listCAsHandler(w http.ResponseWriter, r *http.Request) {
	cas, err := s.certManager.ListAllCAs()
	if err != nil {
		http.Error(w, "Failed to list CAs", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(cas))
	for _, c := range cas {
		out = append(out, c.ToJSON())
	}
	writeJSON(w, out)
}

func (s *Server) deleteCAHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}
	err = s.certManager.DeleteCA(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Device Handlers

func (s *Server) registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID   string `json:"device_id"`
		TPMEnabled bool   `json:"tmp_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" {
		http.Error(w, "Invalid device registration", http.StatusBadRequest)
		return
	}
	fingerprint := device.GenerateFingerprint(req.DeviceID)
	dev := models.NewDevice(req.DeviceID, fingerprint, req.TPMEnabled)
	if err := s.saveDevice(dev); err != nil {
		http.Error(w, "Failed to register device", http.StatusInternalServerError)
		return
	}
	writeJSONCreated(w, dev.ToJSON())
}

func (s *Server) getDeviceHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["deviceId"]
	dev, err := s.getDeviceByID(deviceID)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	writeJSON(w, dev.ToJSON())
}

func (s *Server) listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := s.listAllDevices()
	if err != nil {
		http.Error(w, "Failed to list devices", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(devices))
	for _, d := range devices {
		out = append(out, d.ToJSON())
	}
	writeJSON(w, out)
}

func (s *Server) updateFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["deviceId"]
	newFP := device.GenerateFingerprint(deviceID)
	if err := s.updateDeviceFingerprint(deviceID, newFP); err != nil {
		http.Error(w, "Failed to update fingerprint", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"device_id":   deviceID,
		"fingerprint": newFP,
		"updated_at":  time.Now(),
	})
}

// User Handlers

func (s *Server) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		http.Error(w, "Invalid user creation", http.StatusBadRequest)
		return
	}
	user := models.NewUser(req.Username, req.Email, req.DeviceID)
	if err := s.saveUser(user); err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}
	writeJSONCreated(w, user.ToJSON())
}

func (s *Server) getUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	user, err := s.getUserByID(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	writeJSON(w, user.ToJSON())
}

func (s *Server) listUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := s.listAllUsers()
	if err != nil {
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		out = append(out, u.ToJSON())
	}
	writeJSON(w, out)
}

// Certificate Handlers

func (s *Server) issueCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID       int    `json:"user_id"`
		DeviceID     string `json:"device_id"`
		CAID         int    `json:"ca_id"`
		DurationDays int    `json:"duration_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid certificate request", http.StatusBadRequest)
		return
	}
	if req.DurationDays == 0 {
		req.DurationDays = 365
	}
	cert, err := s.certManager.IssueCertificate(req.UserID, req.DeviceID, req.CAID, req.DurationDays)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to issue certificate: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONCreated(w, cert.ToJSON())
}

func (s *Server) getCertificateHandler(w http.ResponseWriter, r *http.Request) {
	serialNumber := mux.Vars(r)["serialNumber"]
	cert, err := s.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	writeJSON(w, cert.ToJSON())
}

func (s *Server) listDeviceCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["deviceId"]
	certs, err := s.certManager.ListCertificatesByDevice(deviceID)
	if err != nil {
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.ToJSON())
	}
	writeJSON(w, out)
}

func (s *Server) listUserCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.Atoi(mux.Vars(r)["userId"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	certs, err := s.certManager.ListCertificatesByUser(userID)
	if err != nil {
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.ToJSON())
	}
	writeJSON(w, out)
}

func (s *Server) listCACertificatesHandler(w http.ResponseWriter, r *http.Request) {
	caID, err := strconv.Atoi(mux.Vars(r)["caId"])
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}
	certs, err := s.certManager.ListCertificatesByCA(caID)
	if err != nil {
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.ToJSON())
	}
	writeJSON(w, out)
}

func (s *Server) revokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serialNumber"]
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid revoke request", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "unspecified"
	}
	err := s.certManager.RevokeCertificate(serial, req.Reason)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke certificate: %v", err), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{
		"message":       "Certificate revoked successfully",
		"serial_number": serial,
		"reason":        req.Reason,
		"revoked_at":    time.Now(),
	})
}

func (s *Server) validateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serialNumber"]
	valid, err := s.certManager.ValidateCertificate(serial)
	resp := map[string]interface{}{
		"serial_number": serial,
		"valid":         valid,
		"validated_at":  time.Now(),
	}
	if err != nil {
		resp["valid"] = false
		resp["error"] = err.Error()
	}
	writeJSON(w, resp)
}

func (s *Server) getCertificateStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.certManager.GetCertificateStats()
	if err != nil {
		http.Error(w, "Failed to get certificate stats", http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

// Certificate Renewal Handlers

func (s *Server) renewCertificateHandler(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serialNumber"]
	var req struct {
		ExtensionDays int `json:"extension_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid renewal request", http.StatusBadRequest)
		return
	}
	if req.ExtensionDays == 0 {
		req.ExtensionDays = 365
	}
	newCert, err := s.renewalMgr.RenewCertificate(serial, req.ExtensionDays)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to renew certificate: %v", err), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{
		"message":         "Certificate renewed successfully",
		"old_serial":      serial,
		"new_certificate": newCert.ToJSON(),
	})
}

func (s *Server) listExpiringCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if val, err := strconv.Atoi(d); err == nil && val > 0 {
			days = val
		}
	}
	certs, err := s.renewalMgr.CheckExpiring(days)
	if err != nil {
		http.Error(w, "Failed to check expiring certificates", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.ToJSON())
	}
	writeJSON(w, map[string]interface{}{
		"days":         days,
		"count":        len(out),
		"certificates": out,
	})
}

func (s *Server) autoRenewHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CheckDays     int `json:"check_days"`
		ExtensionDays int `json:"extension_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.CheckDays == 0 {
		req.CheckDays = 30
	}
	if req.ExtensionDays == 0 {
		req.ExtensionDays = 365
	}
	count, err := s.renewalMgr.AutoRenewExpiring(req.CheckDays, req.ExtensionDays)
	if err != nil {
		http.Error(w, fmt.Sprintf("Auto-renewal failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"message":        "Auto-renewal completed",
		"renewed_count":  count,
		"check_days":     req.CheckDays,
		"extension_days": req.ExtensionDays,
		"timestamp":      time.Now(),
	})
}

func (s *Server) getRenewalInfoHandler(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serialNumber"]
	info, err := s.renewalMgr.GetRenewalInfo(serial)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get renewal info: %v", err), http.StatusNotFound)
		return
	}
	writeJSON(w, info)
}

func (s *Server) getRenewalStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.renewalMgr.GetRenewalStatistics()
	if err != nil {
		http.Error(w, "Failed to get renewal stats", http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) bulkRenewHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SerialNumbers []string `json:"serial_numbers"`
		ExtensionDays int      `json:"extension_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.SerialNumbers) == 0 {
		http.Error(w, "Invalid bulk renew request", http.StatusBadRequest)
		return
	}
	if req.ExtensionDays == 0 {
		req.ExtensionDays = 365
	}
	result, err := s.renewalMgr.BulkRenewCertificates(req.SerialNumbers, req.ExtensionDays)
	if err != nil {
		http.Error(w, fmt.Sprintf("Bulk renewal failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

// TPM Handlers

func (s *Server) tpmInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := s.tpmManager.GetTPMInfo()
	writeJSON(w, info)
}

func (s *Server) tpmGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyName string `json:"key_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyName == "" {
		http.Error(w, "Invalid or missing key_name", http.StatusBadRequest)
		return
	}
	keyHandle, err := s.tpmManager.GenerateKey(req.KeyName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate key: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"key_name":    req.KeyName,
		"key_handle":  fmt.Sprintf("%x", keyHandle),
		"generated_at": time.Now(),
	})
}

func (s *Server) tpmAttestHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["deviceId"]
	attestation, err := s.tpmManager.AttestDevice(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create attestation: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"device_id":   deviceID,
		"attestation": fmt.Sprintf("%x", attestation),
		"created_at":  time.Now(),
	})
}

func (s *Server) tpmEncryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyHandle string `json:"key_handle"`
		Data      string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyHandle == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	encrypted, err := s.tpmManager.EncryptData([]byte(req.KeyHandle), []byte(req.Data))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encrypt data: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"encrypted_data": fmt.Sprintf("%x", encrypted),
		"encrypted_at":   time.Now(),
	})
}

func (s *Server) tpmDecryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyHandle     string `json:"key_handle"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyHandle == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	decrypted, err := s.tpmManager.DecryptData([]byte(req.KeyHandle), []byte(req.EncryptedData))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decrypt data: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"decrypted_data": string(decrypted),
		"decrypted_at":   time.Now(),
	})
}

func (s *Server) tpmQuoteHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	quote, err := s.tpmManager.GetTPMQuote([]byte(req.Nonce))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get TPM quote: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"quote":      fmt.Sprintf("%x", quote),
		"nonce":      req.Nonce,
		"created_at": time.Now(),
	})
}

func (s *Server) tpmMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.tpmManager.GetTPMMetrics()
	writeJSON(w, metrics)
}

// Database Handlers

func (s *Server) databaseStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := s.db.GetStats()
	if version, err := s.db.GetDatabaseVersion(); err == nil {
		stats["version"] = version
	}
	if size, err := s.db.GetDatabaseSize(); err == nil {
		stats["database_size"] = size
	}
	if tblSizes, err := s.db.GetTableSizes(); err == nil {
		stats["table_sizes"] = tblSizes
	}
	writeJSON(w, stats)
}

func (s *Server) databaseHealthHandler(w http.ResponseWriter, r *http.Request) {
	err := s.db.HealthCheck()
	health := map[string]interface{}{
		"healthy":   err == nil,
		"timestamp": time.Now(),
	}
	if err != nil {
		health["error"] = err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSON(w, health)
}

// Database helper methods for Devices, Users, CA (see previous message) should be included here unchanged.

func (s *Server) saveDevice(device *models.Device) error {
	query := `
		INSERT INTO devices (device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`
	return s.db.QueryRow(query,
		device.DeviceID, device.Fingerprint, device.TPMEnabled,
		device.CreatedAt, device.LastSeen, device.UpdatedAt,
	).Scan(&device.ID)
}

func (s *Server) getDeviceByID(deviceID string) (*models.Device, error) {
	query := `
		SELECT id, device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at
		FROM devices
		WHERE device_id = $1
	`
	device := &models.Device{}
	err := s.db.QueryRow(query, deviceID).Scan(
		&device.ID, &device.DeviceID, &device.Fingerprint, &device.TPMEnabled,
		&device.CreatedAt, &device.LastSeen, &device.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found")
	} else if err != nil {
		return nil, fmt.Errorf("error getting device: %w", err)
	}
	return device, nil
}

func (s *Server) listAllDevices() ([]*models.Device, error) {
	query := `
		SELECT id, device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at
		FROM devices
		ORDER BY last_seen DESC
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("error querying devices: %w", err)
	}
	defer rows.Close()

	var devices []*models.Device
	for rows.Next() {
		d := &models.Device{}
		if err := rows.Scan(
			&d.ID, &d.DeviceID, &d.Fingerprint, &d.TPMEnabled,
			&d.CreatedAt, &d.LastSeen, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("error scanning device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (s *Server) updateDeviceFingerprint(deviceID, fingerprint string) error {
	query := `
		UPDATE devices
		SET fingerprint=$2, last_seen=NOW(), updated_at=NOW()
		WHERE device_id=$1
	`
	res, err := s.db.Exec(query, deviceID, fingerprint)
	if err != nil {
		return fmt.Errorf("error updating device fingerprint: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// Users

func (s *Server) saveUser(user *models.User) error {
	query := `
		INSERT INTO users (username, email, device_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	return s.db.QueryRow(query,
		user.Username, user.Email, user.DeviceID,
		user.CreatedAt, user.UpdatedAt,
	).Scan(&user.ID)
}

func (s *Server) getUserByID(id int) (*models.User, error) {
	query := `
		SELECT id, username, email, device_id, created_at, updated_at
		FROM users
		WHERE id=$1
	`
	user := &models.User{}
	var email, deviceID sql.NullString
	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &email, &deviceID,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	} else if err != nil {
		return nil, fmt.Errorf("error getting user: %w", err)
	}
	if email.Valid {
		user.Email = email.String
	}
	if deviceID.Valid {
		user.DeviceID = deviceID.String
	}
	return user, nil
}

func (s *Server) listAllUsers() ([]*models.User, error) {
	query := `
		SELECT id, username, email, device_id, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("error querying users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		var email, deviceID sql.NullString
		if err := rows.Scan(
			&u.ID, &u.Username, &email, &deviceID,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("error scanning user: %w", err)
		}
		if email.Valid {
			u.Email = email.String
		}
		if deviceID.Valid {
			u.DeviceID = deviceID.String
		}
		users = append(users, u)
	}
	return users, nil
}

// Certificate Authorities (CA)

func (s *Server) saveCA(ca *models.CA) error {
	query := `
		INSERT INTO certificate_authorities (name, cert_pem, key_pem, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	return s.db.QueryRow(query,
		ca.Name, ca.CertPEM, ca.KeyPEM,
		ca.CreatedAt, ca.UpdatedAt,
	).Scan(&ca.ID)
}

func (s *Server) getCAByID(id int) (*models.CA, error) {
	query := `
		SELECT id, name, cert_pem, key_pem, created_at, updated_at
		FROM certificate_authorities
		WHERE id=$1
	`
	ca := &models.CA{}
	err := s.db.QueryRow(query, id).Scan(
		&ca.ID, &ca.Name, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("CA not found")
	} else if err != nil {
		return nil, fmt.Errorf("error getting CA: %w", err)
	}
	return ca, nil
}

func (s *Server) listAllCAs() ([]*models.CA, error) {
	query := `
		SELECT id, name, cert_pem, key_pem, created_at, updated_at
		FROM certificate_authorities
		ORDER BY created_at DESC
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("error querying CAs: %w", err)
	}
	defer rows.Close()

	var cas []*models.CA
	for rows.Next() {
		c := &models.CA{}
		if err := rows.Scan(&c.ID, &c.Name, &c.CertPEM, &c.KeyPEM, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("error scanning CA: %w", err)
		}
		cas = append(cas, c)
	}
	return cas, nil
}

func (s *Server) deleteCA(id int) error {
	query := `
		DELETE FROM certificate_authorities
		WHERE id=$1
	`
	res, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("error deleting CA: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("error checking delete result: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("CA not found")
	}
	return nil
}
