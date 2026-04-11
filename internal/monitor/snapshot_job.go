package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// snapshotChecker is the interface satisfied by vault.SnapshotChecker.
type snapshotChecker interface {
	CheckSnapshot(ctx context.Context) (*vault.SnapshotInfo, error)
}

// SnapshotJob checks whether raft snapshot data is reachable and reports
// an alert when the raft index is zero (no committed entries) or the
// checker itself returns an error.
type SnapshotJob struct {
	checker  snapshotChecker
	notifier alertSender
}

// NewSnapshotJob constructs a SnapshotJob.
func NewSnapshotJob(checker snapshotChecker, notifier alertSender) *SnapshotJob {
	return &SnapshotJob{checker: checker, notifier: notifier}
}

// Run executes the snapshot check and sends an alert when necessary.
func (j *SnapshotJob) Run(ctx context.Context) error {
	info, err := j.checker.CheckSnapshot(ctx)
	if err != nil {
		a := Alert{
			Level:   LevelWarning,
			Message: fmt.Sprintf("snapshot check failed: %v", err),
		}
		return j.notifier.Send(ctx, a)
	}

	if info.Index == 0 {
		a := Alert{
			Level:   LevelWarning,
			Message: "raft snapshot index is zero — no committed entries detected",
		}
		return j.notifier.Send(ctx, a)
	}

	return nil
}
