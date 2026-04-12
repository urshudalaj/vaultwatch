package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/your-org/vaultwatch/internal/vault"
)

type stubOktaChecker struct {
	role *vault.OktaRole
	err  error
}

func (s *stubOktaChecker) GetOktaRole(_, _ string) (*vault.OktaRole, error) {
	return s.role, s.err
}

func oktaJobWithStub(role *vault.OktaRole, err error) *OktaJob {
	return NewOktaJob(&stubOktaChecker{role: role, err: err}, OktaJobConfig{
		Mount: "okta",
		Role:  "dev-team",
	})
}

func TestOktaJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	job := oktaJobWithStub(&vault.OktaRole{
		Mount:  "okta",
		Name:   "dev-team",
		TTL:    "1h",
		MaxTTL: "24h",
	}, nil)

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestOktaJob_AlertWhenTTLMissing(t *testing.T) {
	job := oktaJobWithStub(&vault.OktaRole{
		Mount:  "okta",
		Name:   "dev-team",
		TTL:    "",
		MaxTTL: "24h",
	}, nil)

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestOktaJob_AlertWhenMaxTTLMissing(t *testing.T) {
	job := oktaJobWithStub(&vault.OktaRole{
		Mount:  "okta",
		Name:   "dev-team",
		TTL:    "1h",
		MaxTTL: "",
	}, nil)

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestOktaJob_AlertWhenBothTTLsMissing(t *testing.T) {
	job := oktaJobWithStub(&vault.OktaRole{
		Mount:  "okta",
		Name:   "dev-team",
		TTL:    "",
		MaxTTL: "",
	}, nil)

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}
}

func TestOktaJob_SkipsAlertOnCheckerError(t *testing.T) {
	job := oktaJobWithStub(nil, errors.New("vault unreachable"))

	_, err := job.Run(context.Background())
	if err == nil {
		t.Error("expected error from checker, got nil")
	}
}
