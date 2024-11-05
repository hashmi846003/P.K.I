package blacklist

var blacklistedCerts = map[string]bool{}

func BlacklistCert(serialNumber string) {
    blacklistedCerts[serialNumber] = true
}

func IsBlacklisted(serialNumber string) bool {
    return blacklistedCerts[serialNumber]
}
