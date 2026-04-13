package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/subtlepseudonym/vaultwatch/internal/vault"
)

type stubOIDCChecker struct {
	role *vault.OIDCRole
	err  error
}

func (s *stubOIDCChecker) GetOIDCRole(_, _ string) (*vault.OIDCRole, error) {
	return s.role, s.err
}

func oidcJobWithStub(role *vault.OIDCRole, err error) *OIDCJob {
	return NewOIDCJob(&stubOIDCChecker{role: role, err: err}, []OIDCJobConfig{
		{Mount: "oidc", Role: "webapp"},
	})
}

func TestOIDCJob_NoAlertWhenConfigured(t *testing.T) {
	job := oidcJobWithStub(&vault.OIDCRole{
		TTL: "1h", MaxTTL: "24h", UserClaim: "sub",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestOIDCJob_AlertWhenTTLMissing(t *testing.T) {
	job := oidcJobWithStub(&vault.OIDCRole{
		TTL: "", MaxTTL: "24h", UserClaim: "sub",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestOIDCJob_AlertWhenMaxTTLMissing(t *testing.T) {
	job := oidcJobWithStub(&vault.OIDCRole{
		TTL: "1h", MaxTTL: "", UserClaim: "sub",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestOIDCJob_AlertWhenUserClaimMissing(t *testing.T) {
	job := oidcJobWithStub(&vault.OIDCRole{
		TTL: "1h", MaxTTL: "24h", UserClaim: "",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert for missing user_claim, got %d", len(alerts))
	}
}

func TestOIDCJob_AlertOnCheckerError(t *testing.T) {
	job := oidcJobWithStub(nil, errors.New("vault unavailable"))
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 critical alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical level, got %v", alerts[0].Level)
	}
}
