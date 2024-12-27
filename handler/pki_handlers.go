// handler/pki_handler.go
package handler

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"encoding/pem"
	"math/big"
	"os"
	"time"
	"fmt"
	"log"
	"crypto/sha256"
	"crypto/ecdsa"
)

// Generate a new RSA private key
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// Generate a Certificate Authority (CA) certificate
func GenerateCACertificate(priv *rsa.PrivateKey, name string) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Create a certificate from the certificate bytes
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Generate a CSR (Certificate Signing Request) for a given private key and subject
func GenerateCSR(priv *rsa.PrivateKey, name string) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{name},
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// Sign a CSR with the CA private key and generate a certificate
func SignCertificate(csr *x509.CertificateRequest, caPriv *rsa.PrivateKey, caCert *x509.Certificate) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Save the private key to a file in PEM format
func SavePrivateKeyToFile(priv *rsa.PrivateKey, filename string) error {
	privFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer privFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return nil
}

// Save the certificate to a file in PEM format
func SaveCertificateToFile(cert *x509.Certificate, filename string) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return nil
}

// Load the certificate from a PEM file
func LoadCertificateFromFile(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Verify a certificate with the CA certificate
func VerifyCertificate(cert *x509.Certificate, caCert *x509.Certificate) error {
	verifyOpts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}

	verifyOpts.Roots.AddCert(caCert)

	_, err := cert.Verify(verifyOpts)
	return err
}

// Check certificate expiration
func CheckCertificateExpiration(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

// Renew a certificate (sign a new certificate using the same private key)
func RenewCertificate(cert *x509.Certificate, csr *x509.CertificateRequest, caPriv *rsa.PrivateKey, caCert *x509.Certificate) (*x509.Certificate, error) {
	// Set the validity period to be 1 year from the current date
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	// Sign the new certificate using the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}

	// Parse the new certificate
	newCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return newCert, nil
}

// Blacklist certificate by storing the serial number
var blacklistedSerialNumbers = map[string]bool{}

// Blacklist a certificate
func BlacklistCertificate(cert *x509.Certificate) {
	blacklistedSerialNumbers[cert.SerialNumber.String()] = true
}

// Check if a certificate is blacklisted
func IsCertificateBlacklisted(cert *x509.Certificate) bool {
	return blacklistedSerialNumbers[cert.SerialNumber.String()]
}
