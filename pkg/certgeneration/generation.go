package certgeneration

import (
    "crypto/x509"
    "crypto/x509/pkix"
    "math/big"
    "time"
)

func GenerateCertificate(privateKey *rsa.PrivateKey) (*x509.Certificate, error) {
    serialNumber, _ := big.NewInt(0).SetString("1234567890", 10)
    cert := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"My Organization"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),
    }
    certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
    if err != nil {
        return nil, err
    }
    return x509.ParseCertificate(certBytes)
}
