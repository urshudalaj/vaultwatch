package monitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubSnapshotChecker struct {
	info *vault.SnapshotInfo
	err  error
}

func (s *stubSnapshotChecker) CheckSnapshot(_ context.Context) (*vault.SnapshotInfo, error) {
	return s.info, s.err
}

func snapshotJobWithStub(checker snapshotChecker) (*SnapshotJob, *recordingNotifier) {
	n := &recordingNotifier{}
	return NewSnapshotJob(checker, n), n
}

func TestSnapshotJob_NoAlertWhenHealthy(t *testing.T) {
	checker := &stubSnapshotChecker{
		info: &vault.SnapshotInfo{Index: 100, Term: 2, Timestamp: time.Now()},
	}
	job, notifier := snapshotJobWithStub(checker)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(notifier.alerts))
	}
}

func TestSnapshotJob_AlertWhenIndexZero(t *testing.T) {
	checker := &stubSnapshotChecker{
		info: &vault.SnapshotInfo{Index: 0, Term: 0, Timestamp: time.Now()},
	}
	job, notifier := snapshotJobWithStub(checker)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
	if notifier.alerts[0].Level != LevelWarning {
		t.Errorf("expected Warning, got %s", notifier.alerts[0].Level)
	}
}

func TestSnapshotJob_AlertOnCheckerError(t *testing.T) {
	checker := &stubSnapshotChecker{err: errors.New("raft unavailable")}
	job, notifier := snapshotJobWithStub(checker)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
}
