package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// OrphanTokenTarget describes an accessor to inspect.
type OrphanTokenTarget struct {
	Accessor string
}

// OrphanTokenJobConfig holds configuration for NewOrphanTokenJob.
type OrphanTokenJobConfig struct {
	Checker interface {
		LookupByAccessor(accessor string) (*vault.OrphanTokenInfo, error)
	}
	Targets []OrphanTokenTarget
}

// NewOrphanTokenJob returns a RunFunc that checks orphan tokens and emits
// alerts when a token is found to be non-orphan or has a TTL below the
// warning threshold (1 hour).
func NewOrphanTokenJob(cfg OrphanTokenJobConfig) RunFunc {
	return func(ctx context.Context) []Alert {
		var alerts []Alert
		for _, t := range cfg.Targets {
			if t.Accessor == "" {
				continue
			}
			info, err := cfg.Checker.LookupByAccessor(t.Accessor)
			if err != nil {
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("orphan token checker: accessor %s: %v", t.Accessor, err),
				})
				continue
			}
			if !info.Orphan {
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("token %s (accessor %s) is not an orphan token", info.DisplayName, info.Accessor),
				})
			}
			const warnTTL = 3600
			if info.TTL > 0 && info.TTL < warnTTL {
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("token %s (accessor %s) TTL is low: %ds", info.DisplayName, info.Accessor, info.TTL),
				})
			}
		}
		return alerts
	}
}
