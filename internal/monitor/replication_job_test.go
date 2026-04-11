package monitor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

// stubReplicationChecker is a test double for ReplicationStatusChecker.
type stubReplicationChecker struct {
	status *monitor.ReplicationStatus
	err    error
}

func (s *stubReplicationChecker) CheckReplication(_ context.Context) (*monitor.ReplicationStatus, error) {
	return s.status, s.err
}

func TestReplicationJob_NoAlertWhenHealthy(t *testing.T) {
	sink := &captureAlertSink{}
	checker := &stubReplicationChecker{
		status: &monitor.ReplicationStatus{
			DRMode: "primary", DRState: "running",
			PerformanceMode: "primary", PerformanceState: "running",
		},
	}
	job := monitor.NewReplicationJob(checker, sink)
	job.Run(context.Background())
	if len(sink.alerts) != 0 {
		t.Fatalf("expected no alerts, got %d", len(sink.alerts))
	}
}

func TestReplicationJob_AlertWhenDRDegraded(t *testing.T) {
	sink := &captureAlertSink{}
	checker := &stubReplicationChecker{
		status: &monitor.ReplicationStatus{
			DRMode: "primary", DRState: "idle",
			PerformanceMode: "disabled",
		},
	}
	job := monitor.NewReplicationJob(checker, sink)
	job.Run(context.Background())
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if !strings.Contains(sink.alerts[0].Message, "DR replication degraded") {
		t.Errorf("unexpected message: %s", sink.alerts[0].Message)
	}
}

func TestReplicationJob_AlertWhenPerformanceDegraded(t *testing.T) {
	sink := &captureAlertSink{}
	checker := &stubReplicationChecker{
		status: &monitor.ReplicationStatus{
			DRMode: "disabled",
			PerformanceMode: "primary", PerformanceState: "idle",
		},
	}
	job := monitor.NewReplicationJob(checker, sink)
	job.Run(context.Background())
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if !strings.Contains(sink.alerts[0].Message, "Performance replication degraded") {
		t.Errorf("unexpected message: %s", sink.alerts[0].Message)
	}
}

func TestReplicationJob_SkipsAlertOnCheckerError(t *testing.T) {
	sink := &captureAlertSink{}
	checker := &stubReplicationChecker{err: fmt.Errorf("vault unreachable")}
	job := monitor.NewReplicationJob(checker, sink)
	job.Run(context.Background())
	if len(sink.alerts) != 0 {
		t.Fatalf("expected no alerts on error, got %d", len(sink.alerts))
	}
}
