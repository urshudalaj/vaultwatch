package monitor

import (
	"context"
	"testing"
	"time"
)

type mockScanner struct {
	paths    []string
	leaseID  string
	duration int
}

func (m *mockScanner) ScanPath(_ context.Context, _ string) ([]string, error) {
	return m.paths, nil
}

func (m *mockScanner) ReadLeaseInfo(_ context.Context, _ string) (string, int, bool, error) {
	return m.leaseID, m.duration, true, nil
}

func TestScanJob_NoAlertsWhenOK(t *testing.T) {
	ch := make(chan Alert, 10)
	scanner := &mockScanner{
		paths:    []string{"secret/db"},
		leaseID:  "lease-1",
		duration: 7200, // 2 hours — well within OK range
	}
	job := NewScanJob(scanner, []string{"secret"}, 30*time.Minute, 10*time.Minute, ch)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(ch))
	}
}

func TestScanJob_AlertOnWarning(t *testing.T) {
	ch := make(chan Alert, 10)
	scanner := &mockScanner{
		paths:    []string{"secret/db"},
		leaseID:  "lease-2",
		duration: 1200, // 20 minutes — inside warning window of 30m
	}
	job := NewScanJob(scanner, []string{"secret"}, 30*time.Minute, 10*time.Minute, ch)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) != 1 {
		t.Errorf("expected 1 alert, got %d", len(ch))
	}
}

func TestScanJob_SkipsEmptyLeaseID(t *testing.T) {
	ch := make(chan Alert, 10)
	scanner := &mockScanner{
		paths:    []string{"secret/static"},
		leaseID:  "",
		duration: 0,
	}
	job := NewScanJob(scanner, []string{"secret"}, 30*time.Minute, 10*time.Minute, ch)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) != 0 {
		t.Errorf("expected 0 alerts for empty lease, got %d", len(ch))
	}
}

func TestScanJob_ContextCancel(t *testing.T) {
	ch := make(chan Alert) // unbuffered — will block
	scanner := &mockScanner{
		paths:    []string{"secret/db"},
		leaseID:  "lease-3",
		duration: 300, // 5 minutes — critical
	}
	job := NewScanJob(scanner, []string{"secret"}, 30*time.Minute, 10*time.Minute, ch)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := job.Run(ctx)
	if err == nil {
		t.Error("expected context cancellation error")
	}
}
