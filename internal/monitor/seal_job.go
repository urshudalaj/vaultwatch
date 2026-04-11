package monitor

import (
	"context"
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// SealStatusChecker is the interface satisfied by vault.SealChecker.
type SealStatusChecker interface {
	CheckSeal(ctx context.Context) (*vault.SealStatus, error)
}

// SealJob checks whether the Vault instance is sealed and emits a critical
// alert if so.
type SealJob struct {
	checker  SealStatusChecker
	alerter  Alerter
	logger   *log.Logger
}

// NewSealJob constructs a SealJob.
func NewSealJob(checker SealStatusChecker, alerter Alerter, logger *log.Logger) *SealJob {
	return &SealJob{
		checker: checker,
		alerter: alerter,
		logger:  logger,
	}
}

// Run executes a single seal-status check and sends an alert when sealed.
func (j *SealJob) Run(ctx context.Context) error {
	status, err := j.checker.CheckSeal(ctx)
	if err != nil {
		j.logger.Printf("seal_job: check failed: %v", err)
		return fmt.Errorf("seal_job: %w", err)
	}

	if !status.Initialized {
		alert := Alert{
			Level:   LevelCritical,
			Message: "Vault is not initialized",
		}
		j.alerter.Send(ctx, alert)
		return nil
	}

	if status.Sealed {
		alert := Alert{
			Level:   LevelCritical,
			Message: fmt.Sprintf("Vault is sealed (cluster: %s, version: %s)", status.ClusterName, status.Version),
		}
		j.alerter.Send(ctx, alert)
		return nil
	}

	j.logger.Printf("seal_job: vault is unsealed (cluster: %s)", status.ClusterName)
	return nil
}
