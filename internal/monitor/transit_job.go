package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// transitKeyGetter retrieves transit key info from Vault.
type transitKeyGetter interface {
	GetKey(ctx context.Context, mount, keyName string) (*vault.TransitKeyInfo, error)
}

// TransitJobConfig configures which transit keys to monitor.
type TransitJobConfig struct {
	Mount   string
	KeyName string
}

// TransitJob checks transit key configuration for security concerns.
type TransitJob struct {
	checker transitKeyGetter
	configs []TransitJobConfig
}

// NewTransitJob returns a TransitJob that monitors the given key configs.
func NewTransitJob(checker transitKeyGetter, configs []TransitJobConfig) *TransitJob {
	return &TransitJob{checker: checker, configs: configs}
}

// Run checks each configured transit key and returns alerts for risky settings.
func (j *TransitJob) Run(ctx context.Context) ([]Alert, error) {
	var alerts []Alert

	for _, cfg := range j.configs {
		info, err := j.checker.GetKey(ctx, cfg.Mount, cfg.KeyName)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("transit: failed to read key %s/%s: %v", cfg.Mount, cfg.KeyName, err),
			})
			continue
		}

		if info.DeletionAllowed {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("transit: key %s/%s has deletion_allowed=true", cfg.Mount, cfg.KeyName),
			})
		}

		if info.Exportable {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("transit: key %s/%s is exportable", cfg.Mount, cfg.KeyName),
			})
		}
	}

	return alerts, nil
}
