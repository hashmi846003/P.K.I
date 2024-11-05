package main

import (
    "fmt"
    "github.com/hashmi846003/PKI-Project/pkg/certgeneration"
    "github.com/hashmi846003/PKI-Project/pkg/certmanager"
    "github.com/hashmi846003/PKI-Project/pkg/blacklist"
    "github.com/hashmi846003/PKI-Project/pkg/certexpiry"
    "github.com/hashmi846003/PKI-Project/pkg/expired"
    "github.com/hashmi846003/PKI-Project/pkg/extend"
)

func main() {
    fmt.Println("PKI Project started")

    // Example usage
    privateKey, _ := certgeneration.GenerateKeyPair()
    cert, _ := certgeneration.GenerateCertificate(privateKey)

    fmt.Println("Generated Certificate:", cert)

    // Save certificate and key
    certmanager.SavePEMFile("cert.pem", "CERTIFICATE", cert.Raw)
    certmanager.SavePEMFile("key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))

    // Check expiry
    if certexpiry.CheckExpiry(cert.NotAfter) {
        fmt.Println("Certificate expired")
    }

    // Blacklist certificate
    blacklist.BlacklistCert(cert.SerialNumber.String())

    // Manage expired certificates
    expired.AddExpiredCert(cert.SerialNumber.String(), cert)

    // Extend validity
    extend.ExtendValidity(cert, 365)
    fmt.Println("Extended Certificate:", cert)
}
