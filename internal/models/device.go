package models

import (
	"time"
)

// Device represents a physical or virtual device
type Device struct {
	ID          int       `json:"id" db:"id"`
	DeviceID    string    `json:"device_id" db:"device_id"`
	Fingerprint string    `json:"fingerprint" db:"fingerprint"`
	TPMEnabled  bool      `json:"tmp_enabled" db:"tmp_enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	LastSeen    time.Time `json:"last_seen" db:"last_seen"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// DeviceStatus represents the status of a device
type DeviceStatus string

const (
	DeviceStatusOnline  DeviceStatus = "online"
	DeviceStatusOffline DeviceStatus = "offline"
	DeviceStatusStale   DeviceStatus = "stale"
)

// NewDevice creates a new device instance
func NewDevice(deviceID, fingerprint string, tmpEnabled bool) *Device {
	now := time.Now()
	return &Device{
		DeviceID:    deviceID,
		Fingerprint: fingerprint,
		TPMEnabled:  tmpEnabled,
		CreatedAt:   now,
		LastSeen:    now,
		UpdatedAt:   now,
	}
}

// UpdateLastSeen updates the last seen timestamp
func (d *Device) UpdateLastSeen() {
	d.LastSeen = time.Now()
}

// GetStatus returns the current status of the device based on last seen time
func (d *Device) GetStatus() DeviceStatus {
	now := time.Now()
	
	// Consider device online if seen within last 5 minutes
	if now.Sub(d.LastSeen) <= 5*time.Minute {
		return DeviceStatusOnline
	}
	
	// Consider device stale if seen within last hour
	if now.Sub(d.LastSeen) <= time.Hour {
		return DeviceStatusStale
	}
	
	// Otherwise offline
	return DeviceStatusOffline
}

// MinutesSinceLastSeen returns minutes since device was last seen
func (d *Device) MinutesSinceLastSeen() int {
	return int(time.Since(d.LastSeen).Minutes())
}

// ToJSON returns device data for JSON serialization
func (d *Device) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"id":                     d.ID,
		"device_id":              d.DeviceID,
		"fingerprint":            d.Fingerprint,
		"tmp_enabled":            d.TPMEnabled,
		"created_at":             d.CreatedAt,
		"last_seen":              d.LastSeen,
		"updated_at":             d.UpdatedAt,
		"status":                 d.GetStatus(),
		"minutes_since_last_seen": d.MinutesSinceLastSeen(),
	}
}

// IsValid checks if the device has required fields
func (d *Device) IsValid() bool {
	return d.DeviceID != "" && d.Fingerprint != ""
}
