package models

import (
	"time"
)

// User represents a system user
type User struct {
	ID        int       `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Email     string    `json:"email" db:"email"`
	DeviceID  string    `json:"device_id" db:"device_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewUser creates a new user instance
func NewUser(username, email, deviceID string) *User {
	now := time.Now()
	return &User{
		Username:  username,
		Email:     email,
		DeviceID:  deviceID,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ToJSON returns user data for JSON serialization
func (u *User) ToJSON() map[string]interface{} {
	result := map[string]interface{}{
		"id":         u.ID,
		"username":   u.Username,
		"created_at": u.CreatedAt,
		"updated_at": u.UpdatedAt,
	}
	
	if u.Email != "" {
		result["email"] = u.Email
	}
	
	if u.DeviceID != "" {
		result["device_id"] = u.DeviceID
	}
	
	return result
}

// IsValid checks if the user has required fields
func (u *User) IsValid() bool {
	return u.Username != ""
}

// HasDevice returns true if user has an associated device
func (u *User) HasDevice() bool {
	return u.DeviceID != ""
}
