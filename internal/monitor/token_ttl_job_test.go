package monitor

import (
	"errors"
	"testing"
	"time"
)

type stubTokenTTLChecker struct {
	info *TokenTTLInfoResult
	err  error
}

func (s *stubTokenTTLChecker) LookupTokenTTL(_ string) (*TokenTTLInfoResult, error) {
	return s.info, s.err
}

func tokenTTLJobWithStub(info *TokenTTLInfoResult, err error, targets []TokenTTLTarget) (*TokenTTLJob, *[]Alert) {
	var alerts []Alert
	checker := &stubTokenTTLChecker{info: info, err: err}
	job := NewTokenTTLJob(checker, targets, func(a Alert) { alerts = append(alerts, a) })
	return job, &alerts
}

func TestTokenTTLJob_NoAlertWhenHealthy(t *testing.T) {
	info := &TokenTTLInfoResult{TTL: 7200, DisplayName: "my-token"}
	targets := []TokenTTLTarget{{Accessor: "abc123", WarnBefore: time.Hour}}
	job, alerts := tokenTTLJobWithStub(info, nil, targets)
	job.Run()
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(*alerts))
	}
}

func TestTokenTTLJob_AlertWhenExpiringSoon(t *testing.T) {
	info := &TokenTTLInfoResult{TTL: 1800, DisplayName: "my-token"}
	targets := []TokenTTLTarget{{Accessor: "abc123", WarnBefore: 2 * time.Hour}}
	job, alerts := tokenTTLJobWithStub(info, nil, targets)
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Warning {
		t.Errorf("expected Warning level, got %v", (*alerts)[0].Level)
	}
}

func TestTokenTTLJob_AlertWhenExpired(t *testing.T) {
	info := &TokenTTLInfoResult{TTL: 0, DisplayName: "expired-token"}
	targets := []TokenTTLTarget{{Accessor: "xyz789", WarnBefore: time.Hour}}
	job, alerts := tokenTTLJobWithStub(info, nil, targets)
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Critical {
		t.Errorf("expected Critical level, got %v", (*alerts)[0].Level)
	}
}

func TestTokenTTLJob_AlertOnCheckerError(t *testing.T) {
	targets := []TokenTTLTarget{{Accessor: "bad-accessor"}}
	job, alerts := tokenTTLJobWithStub(nil, errors.New("vault unreachable"), targets)
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Critical {
		t.Errorf("expected Critical level, got %v", (*alerts)[0].Level)
	}
}

func TestTokenTTLJob_UsesDefaultWarnBefore(t *testing.T) {
	// TTL of 23 hours should trigger warning with default 24h threshold
	info := &TokenTTLInfoResult{TTL: int((23 * time.Hour).Seconds()), DisplayName: "soon"}
	targets := []TokenTTLTarget{{Accessor: "def456"}} // WarnBefore is zero => default 24h
	job, alerts := tokenTTLJobWithStub(info, nil, targets)
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert with default warn threshold, got %d", len(*alerts))
	}
}
