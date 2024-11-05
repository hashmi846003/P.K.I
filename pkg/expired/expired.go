package expired

import (
    "crypto/x509"
)

var expiredCerts = map[string]*x509.Certificate{}

func AddExpiredCert(serialNumber string, cert *x509.Certificate) {
    expiredCerts[serialNumber] = cert
}

func GetExpiredCert(serialNumber string) (*x509.Certificate, bool) {
    cert, found := expiredCerts[serialNumber]
    return cert, found
}
