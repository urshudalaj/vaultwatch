package monitor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

type stubTokenExpiryChecker struct {
	info monitor.TokenExpiryInfo
	err  error
}

func (s *stubTokenExpiryChecker) LookupSelf(_ context.Context) (monitor.TokenExpiryInfo, error) {
	return s.info, s.err
}

func TestTokenExpiryJob_NoAlertWhenHealthy(t *testing.T) {
	stub := &stubTokenExpiryChecker{
		info: monitor.TokenExpiryInfo{
			DisplayName: "ci-token",
			ExpireTime:  time.Now().Add(24 * time.Hour),
			Renewable:   true,
			TTL:         86400,
		},
	}
	job := monitor.NewTokenExpiryJob(stub, 1*time.Hour)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestTokenExpiryJob_AlertWhenExpiringSoon(t *testing.T) {
	stub := &stubTokenExpiryChecker{
		info: monitor.TokenExpiryInfo{
			DisplayName: "ci-token",
			ExpireTime:  time.Now().Add(30 * time.Minute),
			Renewable:   true,
			TTL:         1800,
		},
	}
	job := monitor.NewTokenExpiryJob(stub, 1*time.Hour)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.Warning {
		t.Errorf("expected Warning level, got %v", alerts[0].Level)
	}
}

func TestTokenExpiryJob_AlertWhenExpired(t *testing.T) {
	stub := &stubTokenExpiryChecker{
		info: monitor.TokenExpiryInfo{
			DisplayName: "old-token",
			ExpireTime:  time.Now().Add(-5 * time.Minute),
		},
	}
	job := monitor.NewTokenExpiryJob(stub, 1*time.Hour)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.Critical {
		t.Errorf("expected Critical level, got %v", alerts[0].Level)
	}
}

func TestTokenExpiryJob_NoAlertForRootToken(t *testing.T) {
	stub := &stubTokenExpiryChecker{
		info: monitor.TokenExpiryInfo{
			DisplayName: "root",
			ExpireTime:  time.Time{}, // zero = no expiry
		},
	}
	job := monitor.NewTokenExpiryJob(stub, 1*time.Hour)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for root token, got %d", len(alerts))
	}
}

func TestTokenExpiryJob_ErrorPropagates(t *testing.T) {
	stub := &stubTokenExpiryChecker{err: errors.New("vault unreachable")}
	job := monitor.NewTokenExpiryJob(stub, 1*time.Hour)
	_, err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
