package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"hashmi846003/P.K.I/internal/config"
	"hashmi846003/P.K.I/internal/database"
	"hashmi846003/P.K.I/internal/server"
	"haashmi846003/P.K.I/internal/tpm"
)

func main() {
	log.Println("🚀 Starting Certificate Manager with PostgreSQL...")

	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf(" No .env file found or error loading it: %v", err)
		log.Println("Continuing with system environment variables...")
	} else {
		log.Println("Loaded configuration from .env file")
	}

	// Load configuration
	cfg := config.LoadConfig()
	
	// Validate configuration
	if err := cfg.ValidateConfig(); err != nil {
		log.Fatalf(" Configuration validation failed: %v", err)
	}
	
	log.Printf(" Configuration loaded:")
	log.Printf("   - Server Port: %d", cfg.ServerPort)
	log.Printf("   - TLS Enabled: %v", cfg.TLSEnabled)
	log.Printf("   - Database: %s", cfg.GetDatabaseInfo())
	log.Printf("   - Log Level: %s", cfg.LogLevel)

	// Initialize TPM
	if err := tpm.InitTPM(); err != nil {
		log.Printf(" TPM initialization failed: %v", err)
	}

	// Connect to PostgreSQL database
	log.Println("🔌 Connecting to PostgreSQL database...")
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf(" Failed to connect to database: %v", err)
	}
	defer func() {
		log.Println(" Closing database connection...")
		db.Close()
	}()

	log.Println(" Database connection established successfully")

	// Test database health
	if err := db.HealthCheck(); err != nil {
		log.Fatalf(" Database health check failed: %v", err)
	}

	// Initialize and start server
	srv, err := server.NewServer(cfg, db)
	if err != nil {
		log.Fatalf(" Failed to create server: %v", err)
	}

	// Graceful shutdown handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf(" Starting server on port %d...", cfg.ServerPort)
		if err := srv.Start(); err != nil {
			log.Fatalf(" Server failed to start: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-c
	log.Println("Shutdown signal received, gracefully shutting down...")
	
	if err := srv.Stop(); err != nil {
		log.Printf("  Error during server shutdown: %v", err)
	}
	
	log.Println(" Server stopped successfully")
}
