package certificate

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"hashmi846003/P.K.I/internal/models"
)

// RenewalManager handles certificate renewal operations
type RenewalManager struct {
	certManager *Manager
}

// NewRenewalManager creates a new renewal manager
func NewRenewalManager(certManager *Manager) *RenewalManager {
	return &RenewalManager{
		certManager: certManager,
	}
}

// RenewCertificate renews an existing certificate
func (rm *RenewalManager) RenewCertificate(serialNumber string, extensionDays int) (*models.Certificate, error) {
	log.Printf("🔄 Renewing certificate with serial: %s", serialNumber)

	// Get existing certificate
	oldCert, err := rm.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate for renewal: %w", err)
	}

	// Check if certificate is revoked
	if oldCert.IsRevoked() {
		return nil, fmt.Errorf("cannot renew revoked certificate")
	}

	// Issue new certificate with same parameters but extended validity
	newCert, err := rm.certManager.IssueCertificate(
		oldCert.UserID,
		oldCert.DeviceID,
		oldCert.CAID,
		extensionDays,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to issue renewed certificate: %w", err)
	}

	// Mark old certificate as revoked with superseded reason
	err = rm.certManager.RevokeCertificate(oldCert.SerialNumber, "superseded")
	if err != nil {
		log.Printf("⚠️  Warning: failed to revoke old certificate %s: %v", oldCert.SerialNumber, err)
		// Continue anyway as new certificate was issued
	}

	log.Printf("✅ Successfully renewed certificate. Old: %s, New: %s", 
		oldCert.SerialNumber, newCert.SerialNumber)

	return newCert, nil
}

// CheckExpiring finds certificates that are expiring within the given number of days
func (rm *RenewalManager) CheckExpiring(days int) ([]*models.Certificate, error) {
	log.Printf("🔍 Checking for certificates expiring within %d days", days)

	// Use PostgreSQL INTERVAL for date arithmetic
	query := `
		SELECT id, serial_number, user_id, device_id, ca_id, cert_pem,
			   private_key_pem, issued_at, expires_at, revoked, revoked_at,
			   revocation_reason, created_at, updated_at
		FROM certificates 
		WHERE expires_at <= CURRENT_TIMESTAMP + INTERVAL '%d days'
		AND expires_at > CURRENT_TIMESTAMP
		AND revoked = FALSE
		ORDER BY expires_at ASC
	`
	
	rows, err := rm.certManager.db.Query(fmt.Sprintf(query, days))
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
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
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
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
	
	log.Printf("📊 Found %d certificates expiring within %d days", len(certificates), days)
	return certificates, nil
}

// AutoRenewExpiring automatically renews certificates that are expiring soon
func (rm *RenewalManager) AutoRenewExpiring(days int, extensionDays int) (int, error) {
	log.Printf("🤖 Starting auto-renewal for certificates expiring within %d days", days)

	expiring, err := rm.CheckExpiring(days)
	if err != nil {
		return 0, fmt.Errorf("failed to get expiring certificates: %w", err)
	}

	renewed := 0
	failed := 0

	for _, cert := range expiring {
		log.Printf("🔄 Attempting to auto-renew certificate: %s", cert.SerialNumber)
		_, err := rm.RenewCertificate(cert.SerialNumber, extensionDays)
		if err != nil {
			log.Printf("❌ Failed to auto-renew certificate %s: %v", cert.SerialNumber, err)
			failed++
			continue
		}
		renewed++
		log.Printf("✅ Successfully auto-renewed certificate: %s", cert.SerialNumber)
	}

	log.Printf("📈 Auto-renewal completed: %d renewed, %d failed out of %d expiring certificates", 
		renewed, failed, len(expiring))
	
	return renewed, nil
}

// GetRenewalInfo returns renewal information for a certificate
func (rm *RenewalManager) GetRenewalInfo(serialNumber string) (map[string]interface{}, error) {
	cert, err := rm.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	now := time.Now()
	timeToExpiry := cert.ExpiresAt.Sub(now)
	daysToExpiry := int(timeToExpiry.Hours() / 24)

	info := map[string]interface{}{
		"serial_number":    cert.SerialNumber,
		"issued_at":        cert.IssuedAt,
		"expires_at":       cert.ExpiresAt,
		"days_to_expiry":   daysToExpiry,
		"hours_to_expiry":  int(timeToExpiry.Hours()),
		"is_expired":       cert.IsExpired(),
		"is_revoked":       cert.IsRevoked(),
		"status":           cert.GetStatus(),
		"renewal_eligible": rm.isRenewalEligible(cert, daysToExpiry),
	}

	if cert.IsRevoked() && cert.RevokedAt != nil {
		info["revoked_at"] = *cert.RevokedAt
		if cert.RevocationReason != nil {
			info["revocation_reason"] = *cert.RevocationReason
		}
	}

	// Add renewal recommendation
	urgency, message := rm.getRenewalUrgency(cert, daysToExpiry)
	info["renewal_urgency"] = urgency
	info["renewal_message"] = message

	return info, nil
}

// GetRenewalStatistics returns statistics about certificate renewals
func (rm *RenewalManager) GetRenewalStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Certificates expiring in 7 days
	expiring7Days, err := rm.CheckExpiring(7)
	if err != nil {
		return nil, fmt.Errorf("failed to check 7-day expiring certificates: %w", err)
	}
	stats["expiring_7_days"] = len(expiring7Days)
	
	// Certificates expiring in 30 days
	expiring30Days, err := rm.CheckExpiring(30)
	if err != nil {
		return nil, fmt.Errorf("failed to check 30-day expiring certificates: %w", err)
	}
	stats["expiring_30_days"] = len(expiring30Days)
	
	// Already expired certificates
	query := `
		SELECT COUNT(*) FROM certificates 
		WHERE expires_at <= CURRENT_TIMESTAMP AND revoked = FALSE
	`
	var expiredCount int
	err = rm.certManager.db.QueryRow(query).Scan(&expiredCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count expired certificates: %w", err)
	}
	stats["already_expired"] = expiredCount
	
	// Certificates renewed in the last 30 days
	query = `
		SELECT COUNT(*) FROM certificates 
		WHERE issued_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
	`
	var recentRenewals int
	err = rm.certManager.db.QueryRow(query).Scan(&recentRenewals)
	if err != nil {
		return nil, fmt.Errorf("failed to count recent renewals: %w", err)
	}
	stats["renewed_last_30_days"] = recentRenewals
	
	// Average certificate lifetime
	query = `
		SELECT AVG(EXTRACT(EPOCH FROM (expires_at - issued_at))/86400) as avg_lifetime_days
		FROM certificates 
		WHERE revoked = FALSE
	`
	var avgLifetime sql.NullFloat64
	err = rm.certManager.db.QueryRow(query).Scan(&avgLifetime)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate average lifetime: %w", err)
	}
	
	if avgLifetime.Valid {
		stats["average_lifetime_days"] = int(avgLifetime.Float64)
	} else {
		stats["average_lifetime_days"] = 0
	}
	
	return stats, nil
}

// ValidateRenewalEligibility checks if a certificate is eligible for renewal
func (rm *RenewalManager) ValidateRenewalEligibility(serialNumber string) (bool, string, error) {
	cert, err := rm.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		return false, "Certificate not found", err
	}
	
	if cert.IsRevoked() {
		return false, "Certificate is revoked", nil
	}
	
	now := time.Now()
	daysToExpiry := int(cert.ExpiresAt.Sub(now).Hours() / 24)
	
	if daysToExpiry > 90 {
		return false, "Certificate is too far from expiration (more than 90 days)", nil
	}
	
	if daysToExpiry < -30 {
		return false, "Certificate has been expired for too long (more than 30 days)", nil
	}
	
	return true, "Certificate is eligible for renewal", nil
}

// BulkRenewCertificates renews multiple certificates in batch
func (rm *RenewalManager) BulkRenewCertificates(serialNumbers []string, extensionDays int) (map[string]interface{}, error) {
	log.Printf("📦 Starting bulk renewal of %d certificates", len(serialNumbers))
	
	results := make(map[string]interface{})
	successful := 0
	failed := 0
	
	for _, serialNumber := range serialNumbers {
		result := make(map[string]interface{})
		
		newCert, err := rm.RenewCertificate(serialNumber, extensionDays)
		if err != nil {
			result["success"] = false
			result["error"] = err.Error()
			failed++
		} else {
			result["success"] = true
			result["new_serial"] = newCert.SerialNumber
			result["new_expires_at"] = newCert.ExpiresAt
			successful++
		}
		
		results[serialNumber] = result
	}
	
	summary := map[string]interface{}{
		"total_requested": len(serialNumbers),
		"successful":      successful,
		"failed":          failed,
		"success_rate":    float64(successful) / float64(len(serialNumbers)) * 100,
		"results":         results,
	}
	
	log.Printf("📊 Bulk renewal completed: %d successful, %d failed (%.1f%% success rate)", 
		successful, failed, summary["success_rate"])
	
	return summary, nil
}

// Helper methods

// isRenewalEligible checks if a certificate is eligible for renewal
func (rm *RenewalManager) isRenewalEligible(cert *models.Certificate, daysToExpiry int) bool {
	if cert.IsRevoked() {
		return false
	}
	
	// Allow renewal within 90 days of expiry or up to 30 days after expiry
	return daysToExpiry <= 90 && daysToExpiry > -30
}

// getRenewalUrgency returns the urgency level and message for renewal
func (rm *RenewalManager) getRenewalUrgency(cert *models.Certificate, daysToExpiry int) (string, string) {
	if cert.IsRevoked() {
		return "revoked", "Certificate is revoked and cannot be renewed"
	}
	
	if daysToExpiry <= 0 {
		return "expired", fmt.Sprintf("Certificate expired %d days ago", -daysToExpiry)
	}
	
	if daysToExpiry <= 7 {
		return "critical", fmt.Sprintf("Certificate expires in %d days - renewal required immediately", daysToExpiry)
	}
	
	if daysToExpiry <= 30 {
		return "warning", fmt.Sprintf("Certificate expires in %d days - renewal recommended", daysToExpiry)
	}
	
	if daysToExpiry <= 90 {
		return "info", fmt.Sprintf("Certificate expires in %d days - renewal eligible", daysToExpiry)
	}
	
	return "normal", "Certificate is valid and does not require renewal yet"
}

// ScheduleRenewal schedules a certificate for automatic renewal (placeholder for job scheduling)
func (rm *RenewalManager) ScheduleRenewal(serialNumber string, renewalDays int, extensionDays int) error {
	cert, err := rm.certManager.GetCertificateBySerial(serialNumber)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert.IsRevoked() {
		return fmt.Errorf("cannot schedule renewal for revoked certificate")
	}

	renewalDate := cert.ExpiresAt.AddDate(0, 0, -renewalDays)
	
	log.Printf("📅 Scheduled certificate %s for renewal on %s (extension: %d days)", 
		serialNumber, renewalDate.Format("2006-01-02"), extensionDays)

	// In a real implementation, this would integrate with a job scheduler like cron or a message queue
	// For now, we just log the schedule
	
	return nil
}
