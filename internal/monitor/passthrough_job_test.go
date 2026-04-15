package monitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubPassthroughChecker struct {
	info *vault.PassthroughInfo
	err  error
}

func (s *stubPassthroughChecker) GetMount(_ string) (*vault.PassthroughInfo, error) {
	return s.info, s.err
}

func passthroughJobWithStub(info *vault.PassthroughInfo, err error, targets []PassthroughTarget) JobFunc {
	return NewPassthroughJob(&stubPassthroughChecker{info: info, err: err}, targets)
}

func TestPassthroughJob_NoAlertWhenTTLsOK(t *testing.T) {
	info := &vault.PassthroughInfo{Mount: "secret", DefaultTTL: 3600, MaxTTL: 7200}
	job := passthroughJobWithStub(info, nil, []PassthroughTarget{
		{Mount: "secret", MinTTL: 1800, MinMaxTTL: 3600},
	})
	alerts, err := job(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestPassthroughJob_AlertWhenDefaultTTLTooLow(t *testing.T) {
	info := &vault.PassthroughInfo{Mount: "secret", DefaultTTL: 600, MaxTTL: 7200}
	job := passthroughJobWithStub(info, nil, []PassthroughTarget{
		{Mount: "secret", MinTTL: 1800, MinMaxTTL: 3600},
	})
	alerts, err := job(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestPassthroughJob_AlertWhenMaxTTLTooLow(t *testing.T) {
	info := &vault.PassthroughInfo{Mount: "secret", DefaultTTL: 3600, MaxTTL: 1200}
	job := passthroughJobWithStub(info, nil, []PassthroughTarget{
		{Mount: "secret", MinTTL: 1800, MinMaxTTL: 3600},
	})
	alerts, err := job(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestPassthroughJob_AlertOnCheckerError(t *testing.T) {
	job := passthroughJobWithStub(nil, fmt.Errorf("vault unreachable"), []PassthroughTarget{
		{Mount: "secret", MinTTL: 1800},
	})
	alerts, err := job(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %v", alerts[0].Level)
	}
}
