package monitor

import "fmt"

// AlertLevel indicates the severity of an alert.
type AlertLevel int

const (
	AlertWarning  AlertLevel = iota // lease expiring soon
	AlertCritical                   // lease expired
)

// Alert is emitted when a secret lease is expiring or has expired.
type Alert struct {
	Lease *SecretLease
	Level AlertLevel
}

// String returns a human-readable description of the alert.
func (a Alert) String() string {
	switch a.Level {
	case AlertWarning:
		return fmt.Sprintf("WARNING: secret %q expires in %s (lease %s)",
			a.Lease.Path, a.Lease.TimeRemaining().Round(1e9), a.Lease.LeaseID)
	case AlertCritical:
		return fmt.Sprintf("CRITICAL: secret %q has EXPIRED (lease %s)",
			a.Lease.Path, a.Lease.LeaseID)
	default:
		return fmt.Sprintf("UNKNOWN alert for secret %q", a.Lease.Path)
	}
}
