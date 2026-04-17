package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// StepDownChecker is the interface satisfied by vault.StepDownChecker.
type StepDownChecker interface {
	CheckLeaderSelf(ctx context.Context) (*vault.StepDownInfo, error)
}

// StepDownJob alerts when the current Vault node is not the active leader,
// which may indicate an unexpected step-down event.
type StepDownJob struct {
	checker StepDownChecker
	alerts  chan<- Alert
}

// NewStepDownJob creates a StepDownJob.
func NewStepDownJob(checker StepDownChecker, alerts chan<- Alert) *StepDownJob {
	return &StepDownJob{checker: checker, alerts: alerts}
}

// Run executes the step-down check once.
func (j *StepDownJob) Run(ctx context.Context) error {
	info, err := j.checker.CheckLeaderSelf(ctx)
	if err != nil {
		return fmt.Errorf("step_down_job: %w", err)
	}

	if !info.IsSelf {
		j.alerts <- Alert{
			Level:   Critical,
			Message: fmt.Sprintf("vault node is not the active leader; current leader: %s", info.LeaderAddr),
			Meta: map[string]string{
				"cluster_id":   info.ClusterID,
				"cluster_name": info.ClusterName,
				"leader_addr":  info.LeaderAddr,
			},
		}
	}
	return nil
}
