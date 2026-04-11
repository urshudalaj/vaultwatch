package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubHealthChecker struct {
	status *vault.HealthStatus
	err    error
}

func (s *stubHealthChecker) Check(_ context.Context) (*vault.HealthStatus, error) {
	return s.status, s.err
}

func TestHealthJob_NoAlertWhenHealthy(t *testing.T) {
	checker := &stubHealthChecker{status: &vault.HealthStatus{Initialized: true, Sealed: false, Standby: false, Version: "1.15.0"}}
	sink := &captureAlertSink{}
	job := NewHealthJob(checker, sink)

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sink.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(sink.alerts))
	}
}

func TestHealthJob_AlertWhenSealed(t *testing.T) {
	checker := &stubHealthChecker{status: &vault.HealthStatus{Initialized: true, Sealed: true, Version: "1.15.0"}}
	sink := &captureAlertSink{}
	job := NewHealthJob(checker, sink)

	_ = job.Run(context.Background())
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if sink.alerts[0].Level != LevelCritical {
		t.Errorf("expected critical alert, got %s", sink.alerts[0].Level)
	}
}

func TestHealthJob_AlertWhenNotInitialized(t *testing.T) {
	checker := &stubHealthChecker{status: &vault.HealthStatus{Initialized: false, Sealed: false}}
	sink := &captureAlertSink{}
	job := NewHealthJob(checker, sink)

	_ = job.Run(context.Background())
	if len(sink.alerts) == 0 {
		t.Fatal("expected at least one alert for uninitialized vault")
	}
}

func TestHealthJob_AlertWhenStandby(t *testing.T) {
	checker := &stubHealthChecker{status: &vault.HealthStatus{Initialized: true, Sealed: false, Standby: true, ClusterName: "prod"}}
	sink := &captureAlertSink{}
	job := NewHealthJob(checker, sink)

	_ = job.Run(context.Background())
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 warning alert, got %d", len(sink.alerts))
	}
	if sink.alerts[0].Level != LevelWarning {
		t.Errorf("expected warning level, got %s", sink.alerts[0].Level)
	}
}

func TestHealthJob_ReturnsErrorOnCheckerFailure(t *testing.T) {
	checker := &stubHealthChecker{err: errors.New("connection refused")}
	sink := &captureAlertSink{}
	job := NewHealthJob(checker, sink)

	if err := job.Run(context.Background()); err == nil {
		t.Fatal("expected error from checker failure")
	}
}
