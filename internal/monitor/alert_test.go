package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestAlertString_Warning(t *testing.T) {
	a := Alert{
		Lease: &SecretLease{
			Path:      "secret/db",
			LeaseID:   "lease-001",
			ExpiresAt: time.Now().Add(2 * time.Hour),
		},
		Level: AlertWarning,
	}
	s := a.String()
	if !strings.Contains(s, "WARNING") {
		t.Errorf("expected WARNING in string, got: %s", s)
	}
	if !strings.Contains(s, "secret/db") {
		t.Errorf("expected path in string, got: %s", s)
	}
}

func TestAlertString_Critical(t *testing.T) {
	a := Alert{
		Lease: &SecretLease{
			Path:      "secret/api",
			LeaseID:   "lease-002",
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		},
		Level: AlertCritical,
	}
	s := a.String()
	if !strings.Contains(s, "CRITICAL") {
		t.Errorf("expected CRITICAL in string, got: %s", s)
	}
	if !strings.Contains(s, "EXPIRED") {
		t.Errorf("expected EXPIRED in string, got: %s", s)
	}
}
