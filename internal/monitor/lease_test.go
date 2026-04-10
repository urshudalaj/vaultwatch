package monitor

import (
	"testing"
	"time"
)

func newLease(expiresIn time.Duration) *SecretLease {
	return &SecretLease{
		Path:      "secret/test",
		LeaseID:   "lease-abc",
		ExpiresAt: time.Now().Add(expiresIn),
		Renewable: true,
	}
}

func TestLeaseStatus_OK(t *testing.T) {
	lease := newLease(48 * time.Hour)
	if got := lease.Status(24 * time.Hour); got != LeaseOK {
		t.Errorf("expected LeaseOK, got %d", got)
	}
}

func TestLeaseStatus_Warning(t *testing.T) {
	lease := newLease(12 * time.Hour)
	if got := lease.Status(24 * time.Hour); got != LeaseWarning {
		t.Errorf("expected LeaseWarning, got %d", got)
	}
}

func TestLeaseStatus_Expired(t *testing.T) {
	lease := newLease(-1 * time.Second)
	if got := lease.Status(24 * time.Hour); got != LeaseExpired {
		t.Errorf("expected LeaseExpired, got %d", got)
	}
}

func TestTimeRemaining_Positive(t *testing.T) {
	lease := newLease(10 * time.Minute)
	if rem := lease.TimeRemaining(); rem <= 0 {
		t.Errorf("expected positive duration, got %s", rem)
	}
}

func TestTimeRemaining_Expired(t *testing.T) {
	lease := newLease(-5 * time.Minute)
	if rem := lease.TimeRemaining(); rem != 0 {
		t.Errorf("expected 0 for expired lease, got %s", rem)
	}
}
