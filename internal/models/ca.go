package models

import (
	"time"
)

// CA represents a Certificate Authority
type CA struct {
	ID        int       `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CertPEM   string    `json:"cert_pem" db:"cert_pem"`
	KeyPEM    string    `json:"key_pem,omitempty" db:"key_pem"` // Omit from JSON for security
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewCA creates a new CA instance
func NewCA(name, certPEM, keyPEM string) *CA {
	now := time.Now()
	return &CA{
		Name:      name,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ToJSON returns CA data safe for JSON serialization (without private key)
func (ca *CA) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"id":         ca.ID,
		"name":       ca.Name,
		"cert_pem":   ca.CertPEM,
		"created_at": ca.CreatedAt,
		"updated_at": ca.UpdatedAt,
	}
}

// IsValid checks if the CA has required fields
func (ca *CA) IsValid() bool {
	return ca.Name != "" && ca.CertPEM != "" && ca.KeyPEM != ""
}
