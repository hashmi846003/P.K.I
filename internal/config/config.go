package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration for the application
type Config struct {
	ServerPort   int
	DatabaseURL  string
	TLSEnabled   bool
	CertFile     string
	KeyFile      string
	CAFile       string
	LogLevel     string
	DBHost       string
	DBPort       int
	DBUser       string
	DBPassword   string
	DBName       string
	DBSSLMode    string
}

// LoadConfig loads configuration from environment variables with defaults
func LoadConfig() *Config {
	config := &Config{
		ServerPort:   getEnvInt("SERVER_PORT", 8443),
		TLSEnabled:   getEnvBool("TLS_ENABLED", false),
		CertFile:     getEnvString("CERT_FILE", "./certs/server.crt"),
		KeyFile:      getEnvString("KEY_FILE", "./certs/server.key"),
		CAFile:       getEnvString("CA_FILE", "./certs/ca.crt"),
		LogLevel:     getEnvString("LOG_LEVEL", "info"),
		DBHost:       getEnvString("DB_HOST", "localhost"),
		DBPort:       getEnvInt("DB_PORT", 5432),
		DBUser:       getEnvString("DB_USER", "postgres"),
		DBPassword:   getEnvString("DB_PASSWORD", "password"),
		DBName:       getEnvString("DB_NAME", "certmanager"),
		DBSSLMode:    getEnvString("DB_SSLMODE", "disable"),
	}
	
	// Priority: DATABASE_URL > individual DB components
	databaseURL := getEnvString("DATABASE_URL", "")
	if databaseURL != "" {
		config.DatabaseURL = databaseURL
	} else {
		config.DatabaseURL = config.buildDatabaseURL()
	}
	
	return config
}

// buildDatabaseURL constructs PostgreSQL connection string from individual components
func (c *Config) buildDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, c.DBSSLMode)
}

// GetDatabaseInfo returns safe database connection info (without password)
func (c *Config) GetDatabaseInfo() string {
	// Parse the DATABASE_URL to extract components safely
	url := c.DatabaseURL
	
	// Hide password for logging
	if strings.Contains(url, "@") {
		parts := strings.Split(url, "@")
		if len(parts) >= 2 {
			userPart := strings.Split(parts, "://")
			if len(userPart) >= 2 {
				userInfo := strings.Split(userPart, ":")
				if len(userInfo) >= 2 {
					// Replace password with asterisks
					safeURL := fmt.Sprintf("%s://%s:***@%s", userPart, userInfo, parts)
					return safeURL
				}
			}
		}
	}
	
	return fmt.Sprintf("postgresql://%s:%d/%s", c.DBHost, c.DBPort, c.DBName)
}

// ValidateConfig validates the configuration
func (c *Config) ValidateConfig() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("database URL is required")
	}
	
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return fmt.Errorf("invalid server port: %d (must be 1-65535)", c.ServerPort)
	}
	
	if c.TLSEnabled {
		if c.CertFile == "" || c.KeyFile == "" {
			return fmt.Errorf("TLS is enabled but cert_file or key_file is missing")
		}
		
		// Check if cert files exist
		if _, err := os.Stat(c.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file does not exist: %s", c.CertFile)
		}
		
		if _, err := os.Stat(c.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file does not exist: %s", c.KeyFile)
		}
	}
	
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	isValidLogLevel := false
	for _, level := range validLogLevels {
		if strings.EqualFold(c.LogLevel, level) {
			isValidLogLevel = true
			break
		}
	}
	if !isValidLogLevel {
		return fmt.Errorf("invalid log level: %s (must be one of: debug, info, warn, error)", c.LogLevel)
	}
	
	return nil
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return strings.EqualFold(c.LogLevel, "debug") || !c.TLSEnabled
}

// GetLogLevel returns the normalized log level
func (c *Config) GetLogLevel() string {
	return strings.ToLower(c.LogLevel)
}

func getEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if boolVal, err := strconv.ParseBool(val); err == nil {
			return boolVal
		}
	}
	return defaultVal
}
