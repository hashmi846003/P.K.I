// main.go
package main

import (
	"fmt"
	"log"
	"time"
	"pki_project/handler"
)

func main() {
	// Generate CA's private key and certificate
	caPriv, err := handler.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("failed to generate CA private key: %v", err)
	}

	caCert, err := handler.GenerateCACertificate(caPriv, "Example CA")
	if err != nil {
		log.Fatalf("failed to generate CA certificate: %v", err)
	}

	// Save the CA's private key and certificate to files
	err = handler.SavePrivateKeyToFile(caPriv, "ca_private_key.pem")
	if err != nil {
		log.Fatalf("failed to save CA private key: %v", err)
	}

	err = handler.SaveCertificateToFile(caCert, "ca_cert.pem")
	if err != nil {
		log.Fatalf("failed to save CA certificate: %v", err)
	}

	// Generate user's private key and CSR
	userPriv, err := handler.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("failed to generate user private key: %v", err)
	}

	userCSR, err := handler.GenerateCSR(userPriv, "example.com")
	if err != nil {
		log.Fatalf("failed to generate user CSR: %v", err)
	}

	// Sign the user's CSR with the CA's private key
	userCert, err := handler.SignCertificate(userCSR, caPriv, caCert)
	if err != nil {
		log.Fatalf("failed to sign user certificate: %v", err)
	}

	// Save the user's private key and certificate to files
	err = handler.SavePrivateKeyToFile(userPriv, "user_private_key.pem")
	if err != nil {
		log.Fatalf("failed to save user private key: %v", err)
	}

	err = handler.SaveCertificateToFile(userCert, "user_cert.pem")
	if err != nil {
		log.Fatalf("failed to save user certificate: %v", err)
	}

	// Check if the certificate has expired
	if handler.CheckCertificateExpiration(userCert) {
		log.Println("The user's certificate has expired.")
	} else {
		log.Println("The user's certificate is valid.")
	}

	// Blacklist the user certificate
	handler.BlacklistCertificate(userCert)

	// Check if the certificate is blacklisted
	if handler.IsCertificateBlacklisted(userCert) {
		log.Println("The user's certificate is blacklisted.")
	} else {
		log.Println("The user's certificate is not blacklisted.")
	}
}
