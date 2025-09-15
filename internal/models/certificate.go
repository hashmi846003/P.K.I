package models

import (
	"time"
)

// Certificate represents an X.509 certificate
type Certificate struct {
	ID                int        `json:"id" db:"id"`
	SerialNumber      string     `json:"serial_number" db:"serial_number"`
	UserID            int        `json:"user_id" db:"user_id"`
	DeviceID          string     `json:"device_id" db:"device_id"`
	CAID              int        `json:"ca_id" db:"ca_id"`
	CertPEM           string     `json:"cert_pem" db:"cert_pem"`
	PrivateKeyPEM     string     `json:"private_key_pem,omitempty" db:"private_key_pem"` // Omit from JSON for security
	IssuedAt          time.Time  `json:"issued_at" db:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at" db:"expires_at"`
	Revoked           bool       `json:"revoked" db:"revoked"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevocationReason  *string    `json:"revocation_reason,omitempty" db:"revocation_reason"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// CertificateStatus represents the status of a certificate
type CertificateStatus string

const (
	CertificateStatusActive   CertificateStatus = "active"
	CertificateStatusExpired  CertificateStatus = "expired"
	CertificateStatusRevoked  CertificateStatus = "revoked"
	CertificateStatusExpiring CertificateStatus = "expiring"
)

// NewCertificate creates a new certificate instance
func NewCertificate(serialNumber string, userID int, deviceID string, caID int, certPEM string, expiresAt time.Time) *Certificate {
	now := time.Now()
	return &Certificate{
		SerialNumber: serialNumber,
		UserID:       userID,
		DeviceID:     deviceID,
		CAID:         caID,
		CertPEM:      certPEM,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
		Revoked:      false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsExpired checks if the certificate is expired
func (c *Certificate) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsRevoked checks if the certificate is revoked
func (c *Certificate) IsRevoked() bool {
	return c.Revoked
}

// GetStatus returns the current status of the certificate
func (c *Certificate) GetStatus() CertificateStatus {
	if c.Revoked {
		return CertificateStatusRevoked
	}
	
	now := time.Now()
	if now.After(c.ExpiresAt) {
		return CertificateStatusExpired
	}
	
	// Check if expiring within 30 days
	if now.AddDate(0, 0, 30).After(c.ExpiresAt) {
		return CertificateStatusExpiring
	}
	
	return CertificateStatusActive
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (c *Certificate) DaysUntilExpiry() int {
	if c.IsExpired() {
		return -int(time.Since(c.ExpiresAt).Hours() / 24)
	}
	return int(time.Until(c.ExpiresAt).Hours() / 24)
}

// ToJSON returns certificate data safe for JSON serialization (without private key)
func (c *Certificate) ToJSON() map[string]interface{} {
	result := map[string]interface{}{
		"id":             c.ID,
		"serial_number":  c.SerialNumber,
		"user_id":        c.UserID,
		"device_id":      c.DeviceID,
		"ca_id":          c.CAID,
		"cert_pem":       c.CertPEM,
		"issued_at":      c.IssuedAt,
		"expires_at":     c.ExpiresAt,
		"revoked":        c.Revoked,
		"created_at":     c.CreatedAt,
		"updated_at":     c.UpdatedAt,
		"status":         c.GetStatus(),
		"days_to_expiry": c.DaysUntilExpiry(),
	}
	
	if c.RevokedAt != nil {
		result["revoked_at"] = *c.RevokedAt
	}
	
	if c.RevocationReason != nil {
		result["revocation_reason"] = *c.RevocationReason
	}
	
	return result
}

// IsValid checks if the certificate has required fields
func (c *Certificate) IsValid() bool {
	return c.SerialNumber != "" && c.UserID > 0 && c.DeviceID != "" && c.CAID > 0 && c.CertPEM != ""
}
