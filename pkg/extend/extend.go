package extend

import (
    "crypto/x509"
    "time"
)

func ExtendValidity(cert *x509.Certificate, additionalDays int) {
    cert.NotAfter = cert.NotAfter.Add(time.Duration(additionalDays) * 24 * time.Hour)
}
