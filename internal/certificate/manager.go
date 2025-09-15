package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"hashmi846003/P.K.I/internal/database"
	"hashmi846003/P.K.I/internal/models"
)

// Manager handles certificate operations
type Manager struct {
	db *database.DB
}

// NewManager creates a new certificate manager
func NewManager(db *database.DB) *Manager {
	return &Manager{db: db}
}

// CreateCA creates a new Certificate Authority
func (m *Manager) CreateCA(name string) (*models.CA, error) {
	log.Printf("🏛️  Creating new CA: %s", name)
	
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{name},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode certificate to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode private key to PEM
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: caKeyDER,
	})

	// Save CA to database using PostgreSQL RETURNING clause
	ca := models.NewCA(name, string(caCertPEM), string(caKeyPEM))
	
	err = m.saveCA(ca)
	if err != nil {
		return nil, fmt.Errorf("failed to save CA to database: %w", err)
	}

	log.Printf("✅ Successfully created CA: %s with ID: %d", name, ca.ID)
	return ca, nil
}

// IssueCertificate issues a new certificate for a user and device
func (m *Manager) IssueCertificate(userID int, deviceID string, caID int, durationDays int) (*models.Certificate, error) {
	log.Printf("📜 Issuing certificate for user %d, device %s", userID, deviceID)

	// Get CA from database
	ca, err := m.getCAByID(caID)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA: %w", err)
	}

	// Parse CA certificate and key
	caCertBlock, _ := pem.Decode([]byte(ca.CertPEM))
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode([]byte(ca.KeyPEM))
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate certificate private key
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Device Certificate"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    fmt.Sprintf("device-%s", deviceID),
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, durationDays),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	certKeyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate private key: %w", err)
	}

	certKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: certKeyDER,
	})

	// Create certificate model
	cert := models.NewCertificate(
		serialNumber.String(),
		userID,
		deviceID,
		caID,
		string(certPEM),
		time.Now().AddDate(0, 0, durationDays),
	)
	cert.PrivateKeyPEM = string(certKeyPEM)

	// Save certificate to database
	err = m.saveCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificate to database: %w", err)
	}

	log.Printf("✅ Successfully issued certificate with serial: %s", cert.SerialNumber)
	return cert, nil
}

// GetCertificateBySerial retrieves a certificate by serial number
func (m *Manager) GetCertificateBySerial(serialNumber string) (*models.Certificate, error) {
	query := `
		SELECT id, serial_number, user_id, device_id, ca_id, cert_pem, 
			   private_key_pem, issued_at, expires_at, revoked, revoked_at, 
			   revocation_reason, created_at, updated_at
		FROM certificates 
		WHERE serial_number = $1
	`
	
	row := m.db.QueryRow(query, serialNumber)
	
	cert := &models.Certificate{}
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	
	err := row.Scan(
		&cert.ID, &cert.SerialNumber, &cert.UserID, &cert.DeviceID,
		&cert.CAID, &cert.CertPEM, &cert.PrivateKeyPEM,
		&cert.IssuedAt, &cert.ExpiresAt, &cert.Revoked, &revokedAt,
		&revocationReason, &cert.CreatedAt, &cert.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	
	if revocationReason.Valid {
		cert.RevocationReason = &revocationReason.String
	}
	
	return cert, nil
}

// ListCertificatesByDevice lists all certificates for a device
func (m *Manager) ListCertificatesByDevice(deviceID string) ([]*models.Certificate, error) {
	query := `
		SELECT id, serial_number, user_id, device_id, ca_id, cert_pem,
			   private_key_pem, issued_at, expires_at, revoked, revoked_at,
			   revocation_reason, created_at, updated_at
		FROM certificates 
		WHERE device_id = $1 
		ORDER BY issued_at DESC
	`
	
	return m.queryCertificates(query, deviceID)
}

// ListCertificatesByUser lists all certificates for a user
func (m *Manager) ListCertificatesByUser(userID int) ([]*models.Certificate, error) {
	query := `
		SELECT id, serial_number, user_id, device_id, ca_id, cert_pem,
			   private_key_pem, issued_at, expires_at, revoked, revoked_at,
			   revocation_reason, created_at, updated_at
		FROM certificates 
		WHERE user_id = $1 
		ORDER BY issued_at DESC
	`
	
	return m.queryCertificates(query, userID)
}

// ListCertificatesByCA lists all certificates for a CA
func (m *Manager) ListCertificatesByCA(caID int) ([]*models.Certificate, error) {
	query := `
		SELECT id, serial_number, user_id, device_id, ca_id, cert_pem,
			   private_key_pem, issued_at, expires_at, revoked, revoked_at,
			   revocation_reason, created_at, updated_at
		FROM certificates 
		WHERE ca_id = $1 
		ORDER BY issued_at DESC
	`
	
	return m.queryCertificates(query, caID)
}

// RevokeCertificate revokes a certificate
func (m *Manager) RevokeCertificate(serialNumber, reason string) error {
	query := `
		UPDATE certificates 
		SET revoked = TRUE, 
		    revoked_at = CURRENT_TIMESTAMP,
		    revocation_reason = $2,
		    updated_at = CURRENT_TIMESTAMP
		WHERE serial_number = $1 AND revoked = FALSE
	`
	
	result, err := m.db.Exec(query, serialNumber, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("certificate not found or already revoked")
	}
	
	log.Printf("🚫 Revoked certificate %s (reason: %s)", serialNumber, reason)
	return nil
}

// ListAllCAs returns all Certificate Authorities
func (m *Manager) ListAllCAs() ([]*models.CA, error) {
	query := `
		SELECT id, name, cert_pem, key_pem, created_at, updated_at
		FROM certificate_authorities 
		ORDER BY created_at DESC
	`
	
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query CAs: %w", err)
	}
	defer rows.Close()
	
	var cas []*models.CA
	
	for rows.Next() {
		ca := &models.CA{}
		err := rows.Scan(&ca.ID, &ca.Name, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CA: %w", err)
		}
		cas = append(cas, ca)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate CAs: %w", err)
	}
	
	return cas, nil
}

// ValidateCertificate validates a certificate's signature and expiration
func (m *Manager) ValidateCertificate(serialNumber string) (bool, error) {
	cert, err := m.GetCertificateBySerial(serialNumber)
	if err != nil {
		return false, err
	}
	
	// Check if revoked
	if cert.IsRevoked() {
		return false, fmt.Errorf("certificate is revoked")
	}
	
	// Check if expired
	if cert.IsExpired() {
		return false, fmt.Errorf("certificate is expired")
	}
	
	// Parse certificate
	certBlock, _ := pem.Decode([]byte(cert.CertPEM))
	if certBlock == nil {
		return false, fmt.Errorf("failed to decode certificate PEM")
	}
	
	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Get CA certificate
	ca, err := m.getCAByID(cert.CAID)
	if err != nil {
		return false, fmt.Errorf("failed to get CA: %w", err)
	}
	
	caCertBlock, _ := pem.Decode([]byte(ca.CertPEM))
	if caCertBlock == nil {
		return false, fmt.Errorf("failed to decode CA certificate PEM")
	}
	
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	
	// Verify signature
	err = x509Cert.CheckSignatureFrom(caCert)
	if err != nil {
		return false, fmt.Errorf("certificate signature verification failed: %w", err)
	}
	
	return true, nil
}

// GetCertificateStats returns statistics about certificates
func (m *Manager) GetCertificateStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total certificates
	var total int
	err := m.db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count total certificates: %w", err)
	}
	stats["total"] = total
	
	// Active certificates (not revoked and not expired)
	var active int
	err = m.db.QueryRow(`
		SELECT COUNT(*) FROM certificates 
		WHERE revoked = FALSE AND expires_at > CURRENT_TIMESTAMP
	`).Scan(&active)
	if err != nil {
		return nil, fmt.Errorf("failed to count active certificates: %w", err)
	}
	stats["active"] = active
	
	// Revoked certificates
	var revoked int
	err = m.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE revoked = TRUE").Scan(&revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to count revoked certificates: %w", err)
	}
	stats["revoked"] = revoked
	
	// Expired certificates (not revoked but expired)
	var expired int
	err = m.db.QueryRow(`
		SELECT COUNT(*) FROM certificates 
		WHERE expires_at <= CURRENT_TIMESTAMP AND revoked = FALSE
	`).Scan(&expired)
	if err != nil {
		return nil, fmt.Errorf("failed to count expired certificates: %w", err)
	}
	stats["expired"] = expired
	
	// Certificates expiring in 30 days
	var expiring int
	err = m.db.QueryRow(`
		SELECT COUNT(*) FROM certificates 
		WHERE expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days' 
		AND expires_at > CURRENT_TIMESTAMP 
		AND revoked = FALSE
	`).Scan(&expiring)
	if err != nil {
		return nil, fmt.Errorf("failed to count expiring certificates: %w", err)
	}
	stats["expiring_30_days"] = expiring
	
	// Statistics by CA
	caStatsQuery := `
		SELECT ca.name, COUNT(c.id) as cert_count
		FROM certificate_authorities ca
		LEFT JOIN certificates c ON ca.id = c.ca_id
		GROUP BY ca.id, ca.name
		ORDER BY cert_count DESC
	`
	
	rows, err := m.db.Query(caStatsQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query CA statistics: %w", err)
	}
	defer rows.Close()
	
	caStats := make(map[string]int)
	for rows.Next() {
		var caName string
		var certCount int
		if err := rows.Scan(&caName, &certCount); err != nil {
			return nil, fmt.Errorf("failed to scan CA stats: %w", err)
		}
		caStats[caName] = certCount
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate CA stats: %w", err)
	}
	
	stats["by_ca"] = caStats
	
	return stats, nil
}

// Helper methods

// saveCA saves a CA to the database using PostgreSQL RETURNING clause
func (m *Manager) saveCA(ca *models.CA) error {
	query := `
		INSERT INTO certificate_authorities (name, cert_pem, key_pem, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	
	err := m.db.QueryRow(query, ca.Name, ca.CertPEM, ca.KeyPEM, ca.CreatedAt, ca.UpdatedAt).Scan(&ca.ID)
	if err != nil {
		return fmt.Errorf("failed to insert CA: %w", err)
	}
	
	return nil
}

// getCAByID retrieves a CA by ID
func (m *Manager) getCAByID(id int) (*models.CA, error) {
	query := `
		SELECT id, name, cert_pem, key_pem, created_at, updated_at
		FROM certificate_authorities 
		WHERE id = $1
	`
	
	row := m.db.QueryRow(query, id)
	
	ca := &models.CA{}
	err := row.Scan(&ca.ID, &ca.Name, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("CA not found")
		}
		return nil, fmt.Errorf("failed to get CA: %w", err)
	}
	
	return ca, nil
}

// saveCertificate saves a certificate to the database using PostgreSQL RETURNING clause
func (m *Manager) saveCertificate(cert *models.Certificate) error {
	query := `
		INSERT INTO certificates (
			serial_number, user_id, device_id, ca_id, 
			cert_pem, private_key_pem, issued_at, expires_at, 
			revoked, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`
	
	err := m.db.QueryRow(query,
		cert.SerialNumber, cert.UserID, cert.DeviceID, cert.CAID,
		cert.CertPEM, cert.PrivateKeyPEM, cert.IssuedAt, cert.ExpiresAt,
		cert.Revoked, cert.CreatedAt, cert.UpdatedAt,
	).Scan(&cert.ID)
	
	if err != nil {
		return fmt.Errorf("failed to insert certificate: %w", err)
	}
	
	return nil
}

// queryCertificates is a helper method to query certificates
func (m *Manager) queryCertificates(query string, args ...interface{}) ([]*models.Certificate, error) {
	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()
	
	var certificates []*models.Certificate
	
	for rows.Next() {
		cert := &models.Certificate{}
		var revokedAt sql.NullTime
		var revocationReason sql.NullString
		
		err := rows.Scan(
			&cert.ID, &cert.SerialNumber, &cert.UserID, &cert.DeviceID,
			&cert.CAID, &cert.CertPEM, &cert.PrivateKeyPEM,
			&cert.IssuedAt, &cert.ExpiresAt, &cert.Revoked, &revokedAt,
			&revocationReason, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		
		if revokedAt.Valid {
			cert.RevokedAt = &revokedAt.Time
		}
		
		if revocationReason.Valid {
			cert.RevocationReason = &revocationReason.String
		}
		
		certificates = append(certificates, cert)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate certificates: %w", err)
	}
	
	return certificates, nil
}

// GetCAByName retrieves a CA by name
func (m *Manager) GetCAByName(name string) (*models.CA, error) {
	query := `
		SELECT id, name, cert_pem, key_pem, created_at, updated_at
		FROM certificate_authorities 
		WHERE name = $1
	`
	
	row := m.db.QueryRow(query, name)
	
	ca := &models.CA{}
	err := row.Scan(&ca.ID, &ca.Name, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("CA not found")
		}
		return nil, fmt.Errorf("failed to get CA: %w", err)
	}
	
	return ca, nil
}

// DeleteCA deletes a CA (only if no certificates exist)
func (m *Manager) DeleteCA(caID int) error {
	// Check if CA has certificates
	var certCount int
	err := m.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_id = $1", caID).Scan(&certCount)
	if err != nil {
		return fmt.Errorf("failed to check CA certificate count: %w", err)
	}
	
	if certCount > 0 {
		return fmt.Errorf("cannot delete CA with existing certificates (%d found)", certCount)
	}
	
	// Delete CA
	result, err := m.db.Exec("DELETE FROM certificate_authorities WHERE id = $1", caID)
	if err != nil {
		return fmt.Errorf("failed to delete CA: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("CA not found")
	}
	
	log.Printf("🗑️  Deleted CA with ID: %d", caID)
	return nil
}
