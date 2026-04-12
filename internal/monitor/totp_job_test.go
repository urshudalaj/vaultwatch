package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubTOTPChecker struct {
	key *vault.TOTPKey
	err error
}

func (s *stubTOTPChecker) GetKey(_, _ string) (*vault.TOTPKey, error) {
	return s.key, s.err
}

func totpJobWithStub(stub *stubTOTPChecker, targets []TOTPKeyTarget) ([]Alert, error) {
	var alerts []Alert
	job := NewTOTPJob(stub, targets, func(a Alert) { alerts = append(alerts, a) })
	return alerts, job(context.Background())
}

func TestTOTPJob_NoAlertWhenConfigured(t *testing.T) {
	stub := &stubTOTPChecker{key: &vault.TOTPKey{
		AccountName: "user@example.com",
		Issuer:      "App",
		Period:      30,
		Digits:      6,
		Algorithm:   "SHA1",
	}}
	alerts, err := totpJobWithStub(stub, []TOTPKeyTarget{{Mount: "totp", KeyName: "mykey"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestTOTPJob_AlertWhenNonStandardPeriod(t *testing.T) {
	stub := &stubTOTPChecker{key: &vault.TOTPKey{
		Period: 60, Algorithm: "SHA1",
	}}
	alerts, err := totpJobWithStub(stub, []TOTPKeyTarget{{Mount: "totp", KeyName: "k"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning level, got %v", alerts[0].Level)
	}
}

func TestTOTPJob_AlertWhenWeakAlgorithm(t *testing.T) {
	stub := &stubTOTPChecker{key: &vault.TOTPKey{
		Period: 30, Algorithm: "MD5",
	}}
	alerts, _ := totpJobWithStub(stub, []TOTPKeyTarget{{Mount: "totp", KeyName: "k"}})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestTOTPJob_AlertOnCheckerError(t *testing.T) {
	stub := &stubTOTPChecker{err: errors.New("connection refused")}
	alerts, _ := totpJobWithStub(stub, []TOTPKeyTarget{{Mount: "totp", KeyName: "k"}})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %v", alerts[0].Level)
	}
}

func TestTOTPJob_EmptyTargets(t *testing.T) {
	stub := &stubTOTPChecker{}
	alerts, err := totpJobWithStub(stub, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for empty targets, got %d", len(alerts))
	}
}
