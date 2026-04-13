package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type stubAppRoleSecretLookup struct {
	info *AppRoleSecretInfo
	err  error
}

func (s *stubAppRoleSecretLookup) LookupSecretID(_, _, _ string) (*AppRoleSecretInfo, error) {
	return s.info, s.err
}

func appRoleSecretTarget() AppRoleSecretTarget {
	return AppRoleSecretTarget{Mount: "approle", RoleID: "my-role", Accessor: "acc-001"}
}

func TestAppRoleSecretJob_NoAlertWhenNotExpiring(t *testing.T) {
	stub := &stubAppRoleSecretLookup{
		info: &AppRoleSecretInfo{
			SecretIDAccessor: "acc-001",
			ExpirationTime:   time.Now().Add(48 * time.Hour).Format(time.RFC3339),
			TTL:              172800,
		},
	}
	job := NewAppRoleSecretJob(stub, []AppRoleSecretTarget{appRoleSecretTarget()}, 24*time.Hour)
	alerts := job(context.Background())
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestAppRoleSecretJob_AlertWhenExpiringSoon(t *testing.T) {
	stub := &stubAppRoleSecretLookup{
		info: &AppRoleSecretInfo{
			SecretIDAccessor: "acc-001",
			ExpirationTime:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			TTL:              3600,
		},
	}
	job := NewAppRoleSecretJob(stub, []AppRoleSecretTarget{appRoleSecretTarget()}, 24*time.Hour)
	alerts := job(context.Background())
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %s", alerts[0].Level)
	}
}

func TestAppRoleSecretJob_AlertWhenExpired(t *testing.T) {
	stub := &stubAppRoleSecretLookup{
		info: &AppRoleSecretInfo{
			SecretIDAccessor: "acc-001",
			ExpirationTime:   time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			TTL:              0,
		},
	}
	job := NewAppRoleSecretJob(stub, []AppRoleSecretTarget{appRoleSecretTarget()}, 24*time.Hour)
	alerts := job(context.Background())
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %s", alerts[0].Level)
	}
}

func TestAppRoleSecretJob_AlertOnLookupError(t *testing.T) {
	stub := &stubAppRoleSecretLookup{err: fmt.Errorf("vault unavailable")}
	job := NewAppRoleSecretJob(stub, []AppRoleSecretTarget{appRoleSecretTarget()}, 24*time.Hour)
	alerts := job(context.Background())
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %s", alerts[0].Level)
	}
}

func TestAppRoleSecretJob_SkipsNonExpiringSecret(t *testing.T) {
	stub := &stubAppRoleSecretLookup{
		info: &AppRoleSecretInfo{SecretIDAccessor: "acc-001", ExpirationTime: "", TTL: 0},
	}
	job := NewAppRoleSecretJob(stub, []AppRoleSecretTarget{appRoleSecretTarget()}, 24*time.Hour)
	alerts := job(context.Background())
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for non-expiring secret, got %d", len(alerts))
	}
}
