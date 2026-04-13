package monitor

import (
	"context"
	"fmt"
	"time"
)

// AppRoleSecretLookup is the interface for looking up AppRole secret ID metadata.
type AppRoleSecretLookup interface {
	LookupSecretID(mount, roleID, accessor string) (*AppRoleSecretInfo, error)
}

// AppRoleSecretInfo mirrors vault.AppRoleSecretInfo to avoid import cycles.
type AppRoleSecretInfo struct {
	SecretIDAccessor string
	ExpirationTime   string
	TTL              int
}

// AppRoleSecretTarget identifies a single secret ID to monitor.
type AppRoleSecretTarget struct {
	Mount    string
	RoleID   string
	Accessor string
}

// NewAppRoleSecretJob creates a job that checks AppRole secret ID expiry.
func NewAppRoleSecretJob(
	checker AppRoleSecretLookup,
	targets []AppRoleSecretTarget,
	warningTTL time.Duration,
) func(ctx context.Context) []Alert {
	return func(ctx context.Context) []Alert {
		var alerts []Alert
		for _, t := range targets {
			info, err := checker.LookupSecretID(t.Mount, t.RoleID, t.Accessor)
			if err != nil {
				alerts = append(alerts, Alert{
					Level:   Critical,
					Message: fmt.Sprintf("approle secret lookup failed for accessor %s: %v", t.Accessor, err),
				})
				continue
			}

			if info.ExpirationTime == "" {
				// No expiry set — non-expiring secret, skip.
				continue
			}

			expiry, err := time.Parse(time.RFC3339, info.ExpirationTime)
			if err != nil {
				alerts = append(alerts, Alert{
					Level:   Warning,
					Message: fmt.Sprintf("approle secret %s has unparseable expiry: %v", t.Accessor, err),
				})
				continue
			}

			remaining := time.Until(expiry)
			switch {
			case remaining <= 0:
				alerts = append(alerts, Alert{
					Level:   Critical,
					Message: fmt.Sprintf("approle secret %s (role %s) has expired", t.Accessor, t.RoleID),
				})
			case remaining <= warningTTL:
				alerts = append(alerts, Alert{
					Level:   Warning,
					Message: fmt.Sprintf("approle secret %s (role %s) expires in %s", t.Accessor, t.RoleID, remaining.Round(time.Second)),
				})
			}
		}
		return alerts
	}
}
