package monitor

import (
	"context"
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// HealthChecker is the interface satisfied by vault.HealthChecker.
type HealthChecker interface {
	Check(ctx context.Context) (*vault.HealthStatus, error)
}

// HealthJob checks Vault's overall health and raises alerts when the instance
// is sealed or uninitialized.
type HealthJob struct {
	checker  HealthChecker
	notifier AlertSink
}

// NewHealthJob constructs a HealthJob.
func NewHealthJob(checker HealthChecker, notifier AlertSink) *HealthJob {
	return &HealthJob{checker: checker, notifier: notifier}
}

// Run executes the health check and dispatches alerts as needed.
func (j *HealthJob) Run(ctx context.Context) error {
	status, err := j.checker.Check(ctx)
	if err != nil {
		log.Printf("health_job: check error: %v", err)
		return err
	}

	if !status.Initialized {
		j.notifier.Send(Alert{
			Level:   LevelCritical,
			Message: "Vault is not initialized",
		})
	}

	if status.Sealed {
		j.notifier.Send(Alert{
			Level:   LevelCritical,
			Message: fmt.Sprintf("Vault is sealed (version %s)", status.Version),
		})
	}

	if status.Standby {
		j.notifier.Send(Alert{
			Level:   LevelWarning,
			Message: fmt.Sprintf("Vault node is in standby mode (cluster: %s)", status.ClusterName),
		})
	}

	return nil
}
