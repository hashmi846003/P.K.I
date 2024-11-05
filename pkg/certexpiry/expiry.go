package certexpiry

import (
    "time"
)

func CheckExpiry(notAfter time.Time) bool {
    return time.Now().After(notAfter)
}
