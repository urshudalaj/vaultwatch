package monitor

import "time"

// LeaseStatus represents the expiry state of a secret lease.
type LeaseStatus int

const (
	LeaseOK      LeaseStatus = iota
	LeaseWarning             // within warning threshold
	LeaseExpired             // already expired
)

// SecretLease holds metadata about a monitored Vault secret.
type SecretLease struct {
	Path      string
	LeaseID   string
	ExpiresAt time.Time
	Renewable bool
}

// Status returns the current LeaseStatus relative to now.
func (s *SecretLease) Status(warningThreshold time.Duration) LeaseStatus {
	now := time.Now()
	if now.After(s.ExpiresAt) {
		return LeaseExpired
	}
	if s.ExpiresAt.Sub(now) <= warningThreshold {
		return LeaseWarning
	}
	return LeaseOK
}

// TimeRemaining returns the duration until the lease expires.
// Returns 0 if already expired.
func (s *SecretLease) TimeRemaining() time.Duration {
	d := time.Until(s.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}
