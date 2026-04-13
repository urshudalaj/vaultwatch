package monitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubRGPGetter struct {
	policy *vault.RGPPolicy
	err    error
}

func (s *stubRGPGetter) GetRGP(_ string) (*vault.RGPPolicy, error) {
	return s.policy, s.err
}

func rgpJobWithStub(policy *vault.RGPPolicy, err error) *RGPJob {
	return NewRGPJob(&stubRGPGetter{policy: policy, err: err}, "test-policy")
}

func TestRGPJob_NoAlertWhenHealthy(t *testing.T) {
	job := rgpJobWithStub(&vault.RGPPolicy{
		Name:             "test-policy",
		Policy:           `main = rule { true }`,
		EnforcementLevel: "hard-mandatory",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestRGPJob_AlertWhenEnforcementLevelMissing(t *testing.T) {
	job := rgpJobWithStub(&vault.RGPPolicy{
		Name:   "test-policy",
		Policy: `main = rule { true }`,
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected alert for missing enforcement level")
	}
}

func TestRGPJob_AlertWhenPolicyBodyEmpty(t *testing.T) {
	job := rgpJobWithStub(&vault.RGPPolicy{
		Name:             "test-policy",
		EnforcementLevel: "hard-mandatory",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected alert for empty policy body")
	}
}

func TestRGPJob_AlertWhenAdvisoryEnforcement(t *testing.T) {
	job := rgpJobWithStub(&vault.RGPPolicy{
		Name:             "test-policy",
		Policy:           `main = rule { true }`,
		EnforcementLevel: "advisory",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected warning alert for advisory enforcement")
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning level, got %v", alerts[0].Level)
	}
}

func TestRGPJob_ErrorOnCheckerFailure(t *testing.T) {
	job := rgpJobWithStub(nil, fmt.Errorf("vault unreachable"))
	_, err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from checker, got nil")
	}
}
