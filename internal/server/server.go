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

	"hashmi846003/P.K.I/internal/certificate"
	"hashmi846003/P.K.I/internal/config"
	"hashmi846003/P.K.I/internal/database"
	"hashmi846003/P.K.I/internal/device"
	"hashmi846003/P.K.I/internal/models"
	"hashmi846003/P.K.I/internal/tpm"
)

// Server represents the HTTP server
type Server struct {
	config      *config.Config
	db          *database.DB
	httpServer  *http.Server
	certManager *certificate.Manager
	renewalMgr  *certificate.RenewalManager
	tpmManager  *tpm.TPMManager
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config, db *database.DB) (*Server, error) {
	certManager := certificate.NewManager(db)
	renewalManager := certificate.NewRenewalManager(certManager)
	tpmManager := tpm.GetTPMManager()

	server := &Server{
		config:      cfg,
		db:          db,
		certManager: certManager,
		renewalMgr:  renewalManager,
		tpmManager:  tpmManager,
	}

	// Setup HTTP server
	server.setupRoutes()

	return server, nil
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() {
	router := mux.NewRouter()

	// Add middleware
	router.Use(s.corsMiddleware)
	router.Use(s.loggingMiddleware)
	router.Use(s.recoveryMiddleware)

	// Health and system endpoints
	router.HandleFunc("/health", s.healthCheckHandler).Methods("GET")
	router.HandleFunc("/info", s.systemInfoHandler).Methods("GET")
	router.HandleFunc("/stats", s.systemStatsHandler).Methods("GET")

	// Certificate Authority endpoints
	router.HandleFunc("/ca", s.createCAHandler).Methods("POST")
	router.HandleFunc("/ca/{id:[0-9]+}", s.getCAHandler).Methods("GET")
	router.HandleFunc("/ca", s.listCAsHandler).Methods("GET")
	router.HandleFunc("/ca/{id:[0-9]+}", s.deleteCAHandler).Methods("DELETE")

	// Device endpoints
	router.HandleFunc("/devices", s.registerDeviceHandler).Methods("POST")
	router.HandleFunc("/devices/{deviceId}", s.getDeviceHandler).Methods("GET")
	router.HandleFunc("/devices/{deviceId}/fingerprint", s.updateFingerprintHandler).Methods("PUT")
	router.HandleFunc("/devices", s.listDevicesHandler).Methods("GET")

	// User endpoints
	router.HandleFunc("/users", s.createUserHandler).Methods("POST")
	router.HandleFunc("/users/{id:[0-9]+}", s.getUserHandler).Methods("GET")
	router.HandleFunc("/users", s.listUsersHandler).Methods("GET")

	// Certificate endpoints
	router.HandleFunc("/certificates", s.issueCertificateHandler).Methods("POST")
	router.HandleFunc("/certificates/{serialNumber}", s.getCertificateHandler).Methods("GET")
	router.HandleFunc("/certificates/device/{deviceId}", s.listDeviceCertificatesHandler).Methods("GET")
	router.HandleFunc("/certificates/user/{userId:[0-9]+}", s.listUserCertificatesHandler).Methods("GET")
	router.HandleFunc("/certificates/ca/{caId:[0-9]+}", s.listCACertificatesHandler).Methods("GET")
	router.HandleFunc("/certificates/{serialNumber}/revoke", s.revokeCertificateHandler).Methods("POST")
	router.HandleFunc("/certificates/{serialNumber}/validate", s.validateCertificateHandler).Methods("GET")
	router.HandleFunc("/certificates/stats", s.getCertificateStatsHandler).Methods("GET")
	
	// Certificate renewal endpoints
	router.HandleFunc("/certificates/{serialNumber}/renew", s.renewCertificateHandler).Methods("POST")
	router.HandleFunc("/certificates/expiring", s.listExpiringCertificatesHandler).Methods("GET")
	router.HandleFunc("/certificates/auto-renew", s.autoRenewHandler).Methods("POST")
	router.HandleFunc("/certificates/{serialNumber}/renewal-info", s.getRenewalInfoHandler).Methods("GET")
	router.HandleFunc("/certificates/renewal-stats", s.getRenewalStatsHandler).Methods("GET")
	router.HandleFunc("/certificates/bulk-renew", s.bulkRenewHandler).Methods("POST")

	// TPM endpoints
	router.HandleFunc("/tmp/info", s.tpmInfoHandler).Methods("GET")
	router.HandleFunc("/tmp/generate-key", s.tmpGenerateKeyHandler).Methods("POST")
	router.HandleFunc("/tmp/attest/{deviceId}", s.tmpAttestHandler).Methods("POST")
	router.HandleFunc("/tmp/encrypt", s.tmpEncryptHandler).Methods("POST")
	router.HandleFunc("/tmp/decrypt", s.tmpDecryptHandler).Methods("POST")
	router.HandleFunc("/tmp/quote", s.tmpQuoteHandler).Methods("POST")
	router.HandleFunc("/tmp/metrics", s.tmpMetricsHandler).Methods("GET")

	// Database endpoints
	router.HandleFunc("/database/stats", s.databaseStatsHandler).Methods("GET")
	router.HandleFunc("/database/health", s.databaseHealthHandler).Methods("GET")

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.ServerPort),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

// Start starts the server
func (s *Server) Start() error {
	log.Printf("🌐 Starting server on port %d", s.config.ServerPort)
	
	if s.config.TLSEnabled {
		log.Printf("🔒 Starting HTTPS server with TLS")
		return s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	} else {
		log.Printf("🌍 Starting HTTP server (TLS disabled)")
		return s.httpServer.ListenAndServe()
	}
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	log.Println("🛑 Stopping server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	return s.httpServer.Shutdown(ctx)
}

// Middleware functions
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
		
		// Create a response writer wrapper to capture status code
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

// Health check endpoint
func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
		"database":  "connected",
		"server_port": s.config.ServerPort,
	}

	// Check database health
	if err := s.db.HealthCheck(); err != nil {
		health["status"] = "unhealthy"
		health["database"] = "error: " + err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Check TPM status
	if s.tmpManager.IsTPMAvailable() {
		health["tmp"] = "available"
	} else {
		health["tmp"] = "simulation_mode"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// System info endpoint
func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	systemInfo := device.GetDetailedSystemInfo()
	systemInfo["tpm"] = s.tmpManager.GetTPMInfo()
	systemInfo["server"] = map[string]interface{}{
		"port":         s.config.ServerPort,
		"tls_enabled":  s.config.TLSEnabled,
		"log_level":    s.config.LogLevel,
		"development":  s.config.IsDevelopment(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(systemInfo)
}

// System stats endpoint
func (s *Server) systemStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"database": s.db.GetStats(),
		"tmp":      s.tmpManager.GetTPMMetrics(),
		"uptime":   time.Since(time.Now().Truncate(time.Hour)).String(),
	}
	
	// Get certificate stats
	if certStats, err := s.certManager.GetCertificateStats(); err == nil {
		stats["certificates"] = certStats
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Create CA endpoint
func (s *Server) createCAHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "CA name is required", http.StatusBadRequest)
		return
	}

	ca, err := s.certManager.CreateCA(req.Name)
	if err != nil {
		log.Printf("❌ Failed to create CA: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create CA: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ca.ToJSON())
}

// Get CA endpoint
func (s *Server) getCAHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}

	ca, err := s.certManager.GetCAByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ca.ToJSON())
}

// List CAs endpoint
func (s *Server) listCAsHandler(w http.ResponseWriter, r *http.Request) {
	cas, err := s.certManager.ListAllCAs()
	if err != nil {
		log.Printf("❌ Failed to list CAs: %v", err)
		http.Error(w, "Failed to list CAs", http.StatusInternalServerError)
		return
	}

	// Convert to safe JSON format
	var response []map[string]interface{}
	for _, ca := range cas {
		response = append(response, ca.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Delete CA endpoint
func (s *Server) deleteCAHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}

	err = s.certManager.DeleteCA(id)
	if err != nil {
		log.Printf("❌ Failed to delete CA: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Register device endpoint
func (s *Server) registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID   string `json:"device_id"`
		TPMEnabled bool   `json:"tmp_enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" {
		http.Error(w, "Device ID is required", http.StatusBadRequest)
		return
	}

	// Generate device fingerprint
	fingerprint := device.GenerateFingerprint(req.DeviceID)

	// Create device model
	deviceModel := models.NewDevice(req.DeviceID, fingerprint, req.TPMEnabled)

	// Save device to database
	err := s.saveDevice(deviceModel)
	if err != nil {
		log.Printf("❌ Failed to save device: %v", err)
		http.Error(w, "Failed to register device", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(deviceModel.ToJSON())
}

// Get device endpoint
func (s *Server) getDeviceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	device, err := s.getDeviceByID(deviceID)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(device.ToJSON())
}

// List devices endpoint
func (s *Server) listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := s.listAllDevices()
	if err != nil {
		log.Printf("❌ Failed to list devices: %v", err)
		http.Error(w, "Failed to list devices", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, device := range devices {
		response = append(response, device.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update fingerprint endpoint
func (s *Server) updateFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	// Generate new fingerprint
	newFingerprint := device.GenerateFingerprint(deviceID)

	// Update in database
	err := s.updateDeviceFingerprint(deviceID, newFingerprint)
	if err != nil {
		log.Printf("❌ Failed to update fingerprint: %v", err)
		http.Error(w, "Failed to update fingerprint", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"device_id":   deviceID,
		"fingerprint": newFingerprint,
		"updated_at":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Create user endpoint
func (s *Server) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		DeviceID string `json:"device_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	user := models.NewUser(req.Username, req.Email, req.DeviceID)
	
	// Save user to database
	err := s.saveUser(user)
	if err != nil {
		log.Printf("❌ Failed to save user: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user.ToJSON())
}

// Get user endpoint
func (s *Server) getUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := s.getUserByID(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user.ToJSON())
}

// List users endpoint
func (s *Server) listUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := s.listAllUsers()
	if err != nil {
		log.Printf("❌ Failed to list users: %v", err)
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, user := range users {
		response = append(response, user.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Issue certificate endpoint
func (s *Server) issueCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID       int    `json:"user_id"`
		DeviceID     string `json:"device_id"`
		CAID         int    `json:"ca_id"`
		DurationDays int    `json:"duration_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Set default duration if not specified
	if req.DurationDays == 0 {
		req.DurationDays = 365 // 1 year default
	}

	cert, err := s.certManager.IssueCertificate(req.UserID, req.DeviceID, req.CAID, req.DurationDays)
	if err != nil {
		log.Printf("❌ Failed to issue certificate: %v", err)
		http.Error(w, fmt.Sprintf("Failed to issue certificate: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert.ToJSON())
}

// Get certificate endpoint
func (s *Server) getCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]

	cert, err := s.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cert.ToJSON())
}

// List device certificates endpoint
func (s *Server) listDeviceCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	certs, err := s.certManager.ListCertificatesByDevice(deviceID)
	if err != nil {
		log.Printf("❌ Failed to list certificates: %v", err)
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, cert := range certs {
		response = append(response, cert.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// List user certificates endpoint
func (s *Server) listUserCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["userId"]
	
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	certs, err := s.certManager.ListCertificatesByUser(userID)
	if err != nil {
		log.Printf("❌ Failed to list certificates: %v", err)
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, cert := range certs {
		response = append(response, cert.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// List CA certificates endpoint
func (s *Server) listCACertificatesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	caIDStr := vars["caId"]
	
	caID, err := strconv.Atoi(caIDStr)
	if err != nil {
		http.Error(w, "Invalid CA ID", http.StatusBadRequest)
		return
	}

	certs, err := s.certManager.ListCertificatesByCA(caID)
	if err != nil {
		log.Printf("❌ Failed to list certificates: %v", err)
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, cert := range certs {
		response = append(response, cert.ToJSON())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Revoke certificate endpoint
func (s *Server) revokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]

	var req struct {
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Reason == "" {
		req.Reason = "unspecified"
	}

	err := s.certManager.RevokeCertificate(serialNumber, req.Reason)
	if err != nil {
		log.Printf("❌ Failed to revoke certificate: %v", err)
		http.Error(w, fmt.Sprintf("Failed to revoke certificate: %v", err), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"message":       "Certificate revoked successfully",
		"serial_number": serialNumber,
		"reason":        req.Reason,
		"revoked_at":    time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Validate certificate endpoint
func (s *Server) validateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]

	valid, err := s.certManager.ValidateCertificate(serialNumber)
	if err != nil {
		response := map[string]interface{}{
			"valid":         false,
			"serial_number": serialNumber,
			"error":         err.Error(),
			"validated_at":  time.Now(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]interface{}{
		"valid":         valid,
		"serial_number": serialNumber,
		"validated_at":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get certificate stats endpoint
func (s *Server) getCertificateStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.certManager.GetCertificateStats()
	if err != nil {
		log.Printf("❌ Failed to get certificate stats: %v", err)
		http.Error(w, "Failed to get certificate stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Renew certificate endpoint
func (s *Server) renewCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]

	var req struct {
		ExtensionDays int `json:"extension_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ExtensionDays == 0 {
		req.ExtensionDays = 365 // 1 year default
	}

	newCert, err := s.renewalMgr.RenewCertificate(serialNumber, req.ExtensionDays)
	if err != nil {
		log.Printf("❌ Failed to renew certificate: %v", err)
		http.Error(w, fmt.Sprintf("Failed to renew certificate: %v", err), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"message":          "Certificate renewed successfully",
		"old_serial":       serialNumber,
		"new_certificate":  newCert.ToJSON(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// List expiring certificates endpoint
func (s *Server) listExpiringCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	daysParam := r.URL.Query().Get("days")
	days := 30 // default to 30 days
	
	if daysParam != "" {
		if parsedDays, err := strconv.Atoi(daysParam); err == nil && parsedDays > 0 {
			days = parsedDays
		}
	}

	certs, err := s.renewalMgr.CheckExpiring(days)
	if err != nil {
		log.Printf("❌ Failed to check expiring certificates: %v", err)
		http.Error(w, "Failed to check expiring certificates", http.StatusInternalServerError)
		return
	}

	var response []map[string]interface{}
	for _, cert := range certs {
		certData := cert.ToJSON()
		response = append(response, certData)
	}

	result := map[string]interface{}{
		"days":         days,
		"count":        len(response),
		"certificates": response,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Auto-renew certificates endpoint
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

	renewed, err := s.renewalMgr.AutoRenewExpiring(req.CheckDays, req.ExtensionDays)
	if err != nil {
		log.Printf("❌ Auto-renewal failed: %v", err)
		http.Error(w, fmt.Sprintf("Auto-renewal failed: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":        "Auto-renewal completed",
		"renewed_count":  renewed,
		"check_days":     req.CheckDays,
		"extension_days": req.ExtensionDays,
		"timestamp":      time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get renewal info endpoint
func (s *Server) getRenewalInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]

	info, err := s.renewalMgr.GetRenewalInfo(serialNumber)
	if err != nil {
		log.Printf("❌ Failed to get renewal info: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get renewal info: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// Get renewal stats endpoint
func (s *Server) getRenewalStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.renewalMgr.GetRenewalStatistics()
	if err != nil {
		log.Printf("❌ Failed to get renewal stats: %v", err)
		http.Error(w, "Failed to get renewal stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Bulk renew endpoint
func (s *Server) bulkRenewHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SerialNumbers []string `json:"serial_numbers"`
		ExtensionDays int      `json:"extension_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.SerialNumbers) == 0 {
		http.Error(w, "Serial numbers are required", http.StatusBadRequest)
		return
	}

	if req.ExtensionDays == 0 {
		req.ExtensionDays = 365
	}

	results, err := s.renewalMgr.BulkRenewCertificates(req.SerialNumbers, req.ExtensionDays)
	if err != nil {
		log.Printf("❌ Bulk renewal failed: %v", err)
		http.Error(w, fmt.Sprintf("Bulk renewal failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// TPM endpoints

func (s *Server) tmpInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := s.tmpManager.GetTPMInfo()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) tmpGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyName string `json:"key_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.KeyName == "" {
		http.Error(w, "Key name is required", http.StatusBadRequest)
		return
	}

	keyHandle, err := s.tmpManager.GenerateKey(req.KeyName)
	if err != nil {
		log.Printf("❌ Failed to generate TPM key: %v", err)
		http.Error(w, fmt.Sprintf("Failed to generate key: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"key_name":     req.KeyName,
		"key_handle":   fmt.Sprintf("%x", keyHandle),
		"generated_at": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) tmpAttestHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	attestation, err := s.tmpManager.AttestDevice(deviceID)
	if err != nil {
		log.Printf("❌ Failed to create device attestation: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create attestation: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"device_id":   deviceID,
		"attestation": fmt.Sprintf("%x", attestation),
		"created_at":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) tmpEncryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyHandle string `json:"key_handle"`
		Data      string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	keyHandle := []byte(req.KeyHandle)
	encrypted, err := s.tmpManager.EncryptData(keyHandle, []byte(req.Data))
	if err != nil {
		log.Printf("❌ Failed to encrypt data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encrypt data: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"encrypted_data": fmt.Sprintf("%x", encrypted),
		"encrypted_at":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) tmpDecryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyHandle     string `json:"key_handle"`
		EncryptedData string `json:"encrypted_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	keyHandle := []byte(req.KeyHandle)
	encryptedData := []byte(req.EncryptedData)

	decrypted, err := s.tmpManager.DecryptData(keyHandle, encryptedData)
	if err != nil {
		log.Printf("❌ Failed to decrypt data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to decrypt data: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"decrypted_data": string(decrypted),
		"decrypted_at":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) tmpQuoteHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	nonce := []byte(req.Nonce)
	quote, err := s.tmpManager.GetTPMQuote(nonce)
	if err != nil {
		log.Printf("❌ Failed to get TPM quote: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get TPM quote: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"quote":      fmt.Sprintf("%x", quote),
		"nonce":      req.Nonce,
		"created_at": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) tmpMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.tmpManager.GetTPMMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Database endpoints
func (s *Server) databaseStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := s.db.GetStats()
	
	// Add additional database information
	if version, err := s.db.GetDatabaseVersion(); err == nil {
		stats["version"] = version
	}
	
	if size, err := s.db.GetDatabaseSize(); err == nil {
		stats["database_size"] = size
	}
	
	if tableSizes, err := s.db.GetTableSizes(); err == nil {
		stats["table_sizes"] = tableSizes
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Database helper methods
func (s *Server) saveDevice(device *models.Device) error {
	query := `
		INSERT INTO devices (device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`
	
	err := s.db.QueryRow(query,
		device.DeviceID, device.Fingerprint, device.TPMEnabled,
		device.CreatedAt, device.LastSeen, device.UpdatedAt,
	).Scan(&device.ID)
	
	if err != nil {
		return fmt.Errorf("failed to insert device: %w", err)
	}
	
	return nil
}

func (s *Server) getDeviceByID(deviceID string) (*models.Device, error) {
	query := `
		SELECT id, device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at
		FROM devices WHERE device_id = $1
	`
	
	row := s.db.QueryRow(query, deviceID)
	device := &models.Device{}
	
	err := row.Scan(&device.ID, &device.DeviceID, &device.Fingerprint, 
		&device.TPMEnabled, &device.CreatedAt, &device.LastSeen, &device.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device not found")
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}
	
	return device, nil
}

func (s *Server) listAllDevices() ([]*models.Device, error) {
	query := `
		SELECT id, device_id, fingerprint, tmp_enabled, created_at, last_seen, updated_at
		FROM devices ORDER BY last_seen DESC
	`
	
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()
	
	var devices []*models.Device
	
	for rows.Next() {
		device := &models.Device{}
		err := rows.Scan(&device.ID, &device.DeviceID, &device.Fingerprint,
			&device.TPMEnabled, &device.CreatedAt, &device.LastSeen, &device.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}
		devices = append(devices, device)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate devices: %w", err)
	}
	
	return devices, nil
}

func (s *Server) updateDeviceFingerprint(deviceID, fingerprint string) error {
	query := `
		UPDATE devices 
		SET fingerprint = $2, last_seen = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE device_id = $1
	`
	
	result, err := s.db.Exec(query, deviceID, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to update device fingerprint: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("device not found")
	}
	
	return nil
}

func (s *Server) saveUser(user *models.User) error {
	query := `
		INSERT INTO users (username, email, device_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	
	err := s.db.QueryRow(query,
		user.Username, user.Email, user.DeviceID, user.CreatedAt, user.UpdatedAt,
	).Scan(&user.ID)
	
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}
	
	return nil
}

func (s *Server) getUserByID(userID int) (*models.User, error) {
	query := `
		SELECT id, username, email, device_id, created_at, updated_at
		FROM users WHERE id = $1
	`
	
	row := s.db.QueryRow(query, userID)
	user := &models.User{}
	
	var email, deviceID sql.NullString
	
	err := row.Scan(&user.ID, &user.Username, &email, &deviceID,
		&user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
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
		FROM users ORDER BY created_at DESC
	`
	
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()
	
	var users []*models.User
	
	for rows.Next() {
		user := &models.User{}
		var email, deviceID sql.NullString
		
		err := rows.Scan(&user.ID, &user.Username, &email, &deviceID,
			&user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		
		if email.Valid {
			user.Email = email.String
		}
		
		if deviceID.Valid {
			user.DeviceID = deviceID.String
		}
		
		users = append(users, user)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate users: %w", err)
	}
	
	return users, nil
}
