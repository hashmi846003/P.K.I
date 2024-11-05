package certmanager

import (
    "crypto/rsa"
    "crypto/x509"
    "crypto/rand"
)

func GenerateKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}
