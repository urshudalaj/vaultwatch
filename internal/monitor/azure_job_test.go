package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/subtlepseudonym/vaultwatch/internal/vault"
)

type stubAzureChecker struct {
	info *vault.AzureRoleInfo
	err  error
}

func (s *stubAzureChecker) GetAzureRole(_, _ string) (*vault.AzureRoleInfo, error) {
	return s.info, s.err
}

func azureJobWithStub(checker AzureRoleGetter) (RunFunc, *[]Alert) {
	var alerts []Alert
	send := func(a Alert) { alerts = append(alerts, a) }
	job := NewAzureJob(checker, AzureJobConfig{Mount: "azure", Role: "my-role"}, send)
	return job, &alerts
}

func TestAzureJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	stub := &stubAzureChecker{info: &vault.AzureRoleInfo{TTL: "1h", MaxTTL: "24h"}}
	job, alerts := azureJobWithStub(stub)
	if err := job(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(*alerts))
	}
}

func TestAzureJob_AlertWhenTTLMissing(t *testing.T) {
	stub := &stubAzureChecker{info: &vault.AzureRoleInfo{TTL: "", MaxTTL: "24h"}}
	job, alerts := azureJobWithStub(stub)
	if err := job(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(*alerts))
	}
}

func TestAzureJob_AlertWhenMaxTTLMissing(t *testing.T) {
	stub := &stubAzureChecker{info: &vault.AzureRoleInfo{TTL: "1h", MaxTTL: ""}}
	job, alerts := azureJobWithStub(stub)
	if err := job(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(*alerts))
	}
}

func TestAzureJob_AlertWhenBothTTLsMissing(t *testing.T) {
	stub := &stubAzureChecker{info: &vault.AzureRoleInfo{TTL: "", MaxTTL: ""}}
	job, alerts := azureJobWithStub(stub)
	if err := job(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(*alerts))
	}
}

func TestAzureJob_ReturnsErrorOnCheckerFailure(t *testing.T) {
	stub := &stubAzureChecker{err: errors.New("vault unreachable")}
	job, _ := azureJobWithStub(stub)
	if err := job(context.Background()); err == nil {
		t.Fatal("expected error from checker failure")
	}
}
