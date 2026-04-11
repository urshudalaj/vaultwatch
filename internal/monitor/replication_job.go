package monitor

import (
	"context"
	"fmt"
	"log"
)

// ReplicationStatusChecker is satisfied by vault.ReplicationChecker.
type ReplicationStatusChecker interface {
	CheckReplication(ctx context.Context) (*ReplicationStatus, error)
}

// ReplicationStatus mirrors the vault package type for the monitor layer.
type ReplicationStatus struct {
	DRMode           string
	DRState          string
	PerformanceMode  string
	PerformanceState string
}

// ReplicationJob monitors Vault replication health and emits alerts when
// replication is degraded or not running as expected.
type ReplicationJob struct {
	checker  ReplicationStatusChecker
	notifier AlertSink
}

// NewReplicationJob creates a ReplicationJob.
func NewReplicationJob(checker ReplicationStatusChecker, notifier AlertSink) *ReplicationJob {
	return &ReplicationJob{checker: checker, notifier: notifier}
}

// Run performs a single replication status check and fires alerts if needed.
func (j *ReplicationJob) Run(ctx context.Context) {
	status, err := j.checker.CheckReplication(ctx)
	if err != nil {
		log.Printf("replication_job: check failed: %v", err)
		return
	}

	if status.DRMode == "primary" && status.DRState != "running" {
		j.notifier.Send(Alert{
			Level:   LevelCritical,
			Message: fmt.Sprintf("DR replication degraded: state=%s", status.DRState),
		})
	}

	if status.PerformanceMode == "primary" && status.PerformanceState != "running" {
		j.notifier.Send(Alert{
			Level:   LevelCritical,
			Message: fmt.Sprintf("Performance replication degraded: state=%s", status.PerformanceState),
		})
	}
}
