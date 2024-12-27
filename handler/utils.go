// handler/utils.go
package handler

import (
	"crypto/pem"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

// Helper function to load private key from file
func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	privPEM, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read private key file: %v", err)
		return nil, err
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
