package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

// DB wraps the sql.DB connection
type DB struct {
	*sql.DB
}

// Connect establishes a connection to the PostgreSQL database
func Connect(databaseURL string) (*DB, error) {
	log.Println("🔗 Opening PostgreSQL connection...")
	
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool for production use
	db.SetMaxOpenConns(25)                      // Maximum open connections
	db.SetMaxIdleConns(5)                       // Maximum idle connections
	db.SetConnMaxLifetime(time.Hour)            // Connection lifetime
	db.SetConnMaxIdleTime(time.Minute * 30)     // Maximum idle time

	// Test the connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println(" PostgreSQL connection successful")

	// Initialize database schema
	if err := initSchema(db); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Printf("🗄️  PostgreSQL database ready with connection pool (max: 25, idle: 5)")
	return &DB{db}, nil
}

// initSchema creates necessary tables with PostgreSQL syntax
func initSchema(db *sql.DB) error {
	log.Println("📋 Initializing database schema...")
	
	schema := `
	-- Enable UUID extension if available (optional for future use)
	-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	-- Certificate Authorities table
	CREATE TABLE IF NOT EXISTS certificate_authorities (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		cert_pem TEXT NOT NULL,
		key_pem TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	-- Devices table
	CREATE TABLE IF NOT EXISTS devices (
		id SERIAL PRIMARY KEY,
		device_id VARCHAR(255) UNIQUE NOT NULL,
		fingerprint VARCHAR(255) NOT NULL,
		tpm_enabled BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255),
		device_id VARCHAR(255),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_users_device_id 
			FOREIGN KEY (device_id) 
			REFERENCES devices(device_id) 
			ON DELETE SET NULL 
			ON UPDATE CASCADE
	);

	-- Certificates table
	CREATE TABLE IF NOT EXISTS certificates (
		id SERIAL PRIMARY KEY,
		serial_number VARCHAR(255) UNIQUE NOT NULL,
		user_id INTEGER NOT NULL,
		device_id VARCHAR(255) NOT NULL,
		ca_id INTEGER NOT NULL,
		cert_pem TEXT NOT NULL,
		private_key_pem TEXT,
		issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		revoked BOOLEAN DEFAULT FALSE,
		revoked_at TIMESTAMP WITH TIME ZONE,
		revocation_reason VARCHAR(100),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_certificates_user_id 
			FOREIGN KEY (user_id) 
			REFERENCES users(id) 
			ON DELETE CASCADE 
			ON UPDATE CASCADE,
		CONSTRAINT fk_certificates_device_id 
			FOREIGN KEY (device_id) 
			REFERENCES devices(device_id) 
			ON DELETE CASCADE 
			ON UPDATE CASCADE,
		CONSTRAINT fk_certificates_ca_id 
			FOREIGN KEY (ca_id) 
			REFERENCES certificate_authorities(id) 
			ON DELETE CASCADE 
			ON UPDATE CASCADE
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
	CREATE INDEX IF NOT EXISTS idx_certificates_device_id ON certificates(device_id);
	CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id);
	CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates(expires_at);
	CREATE INDEX IF NOT EXISTS idx_certificates_revoked ON certificates(revoked) WHERE revoked = FALSE;
	CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON certificates(serial_number);
	CREATE INDEX IF NOT EXISTS idx_certificates_issued_at ON certificates(issued_at);
	CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);
	CREATE INDEX IF NOT EXISTS idx_devices_tmp_enabled ON devices(tmp_enabled);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_device_id ON users(device_id);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_ca_name ON certificate_authorities(name);
	CREATE INDEX IF NOT EXISTS idx_ca_created_at ON certificate_authorities(created_at);

	-- Create partial indexes for active certificates (performance optimization)
	CREATE INDEX IF NOT EXISTS idx_certificates_active 
		ON certificates(expires_at, device_id) 
		WHERE revoked = FALSE;

	-- Create composite index for renewal queries
	CREATE INDEX IF NOT EXISTS idx_certificates_renewal 
		ON certificates(expires_at, revoked, ca_id) 
		WHERE revoked = FALSE;
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	// Create triggers for updated_at timestamps (PostgreSQL specific)
	triggerSQL := `
	-- Function to update updated_at column
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
	BEGIN
		NEW.updated_at = CURRENT_TIMESTAMP;
		RETURN NEW;
	END;
	$$ language 'plpgsql';

	-- Triggers for each table
	DROP TRIGGER IF EXISTS update_certificate_authorities_updated_at ON certificate_authorities;
	CREATE TRIGGER update_certificate_authorities_updated_at 
		BEFORE UPDATE ON certificate_authorities 
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

	DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;
	CREATE TRIGGER update_devices_updated_at 
		BEFORE UPDATE ON devices 
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

	DROP TRIGGER IF EXISTS update_users_updated_at ON users;
	CREATE TRIGGER update_users_updated_at 
		BEFORE UPDATE ON users 
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

	DROP TRIGGER IF EXISTS update_certificates_updated_at ON certificates;
	CREATE TRIGGER update_certificates_updated_at 
		BEFORE UPDATE ON certificates 
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
	`

	_, err = db.Exec(triggerSQL)
	if err != nil {
		log.Printf("⚠️  Warning: Failed to create triggers: %v", err)
		// Don't fail the initialization if triggers fail
	} else {
		log.Println("✅ Database triggers created successfully")
	}

	log.Println("✅ Database schema initialized successfully")
	return nil
}

// HealthCheck performs a comprehensive health check on the database
func (db *DB) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Basic ping test
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	
	// Test a simple query
	var result int
	err := db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("database query test failed: %w", err)
	}
	
	if result != 1 {
		return fmt.Errorf("database query returned unexpected result: %d", result)
	}
	
	// Test table existence
	var tableCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) 
		FROM information_schema.tables 
		WHERE table_schema = 'public' 
		AND table_name IN ('certificate_authorities', 'devices', 'users', 'certificates')
	`).Scan(&tableCount)
	
	if err != nil {
		return fmt.Errorf("failed to check table existence: %w", err)
	}
	
	if tableCount != 4 {
		return fmt.Errorf("expected 4 tables, found %d", tableCount)
	}
	
	log.Println("✅ Database health check passed")
	return nil
}

// GetStats returns database connection pool statistics
func (db *DB) GetStats() map[string]interface{} {
	stats := db.DB.Stats()
	return map[string]interface{}{
		"max_open_connections":     stats.MaxOpenConnections,
		"open_connections":         stats.OpenConnections,
		"in_use":                  stats.InUse,
		"idle":                    stats.Idle,
		"wait_count":              stats.WaitCount,
		"wait_duration":           stats.WaitDuration.String(),
		"max_idle_closed":         stats.MaxIdleClosed,
		"max_idle_time_closed":    stats.MaxIdleTimeClosed,
		"max_lifetime_closed":     stats.MaxLifetimeClosed,
	}
}

// Close gracefully closes the database connection
func (db *DB) Close() error {
	if db.DB != nil {
		log.Println("🔌 Closing database connection...")
		return db.DB.Close()
	}
	return nil
}

// BeginTx starts a new transaction
func (db *DB) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return db.DB.BeginTx(ctx, nil)
}

// GetDatabaseVersion returns the PostgreSQL version
func (db *DB) GetDatabaseVersion() (string, error) {
	var version string
	err := db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("failed to get database version: %w", err)
	}
	return version, nil
}

// GetDatabaseSize returns the size of the database
func (db *DB) GetDatabaseSize() (string, error) {
	var size string
	err := db.QueryRow(`
		SELECT pg_size_pretty(pg_database_size(current_database()))
	`).Scan(&size)
	if err != nil {
		return "", fmt.Errorf("failed to get database size: %w", err)
	}
	return size, nil
}

// GetTableSizes returns the sizes of all tables
func (db *DB) GetTableSizes() (map[string]string, error) {
	query := `
		SELECT 
			schemaname||'.'||tablename as table_name,
			pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
		FROM pg_tables 
		WHERE schemaname = 'public'
		ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
	`
	
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query table sizes: %w", err)
	}
	defer rows.Close()
	
	sizes := make(map[string]string)
	for rows.Next() {
		var tableName, size string
		if err := rows.Scan(&tableName, &size); err != nil {
			return nil, fmt.Errorf("failed to scan table size: %w", err)
		}
		sizes[tableName] = size
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table sizes: %w", err)
	}
	
	return sizes, nil
}
