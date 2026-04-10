package monitor

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// TokenJobConfig holds configuration for the token monitoring job.
type TokenJobConfig struct {
	// WarnThreshold is the TTL remaining below which a warning alert is raised.
	WarnThreshold time.Duration
	// CriticalThreshold is the TTL remaining below which a critical alert is raised.
	CriticalThreshold time.Duration
	// AutoRenew enables automatic token renewal when below WarnThreshold.
	AutoRenew bool
	// RenewIncrement is the number of seconds to request on renewal.
	RenewIncrement int
}

// TokenJob monitors the Vault token TTL and emits alerts.
type TokenJob struct {
	watcher *vault.TokenWatcher
	cfg     TokenJobConfig
	alerts  chan<- Alert
}

// NewTokenJob creates a TokenJob that sends alerts to the provided channel.
func NewTokenJob(watcher *vault.TokenWatcher, cfg TokenJobConfig, alerts chan<- Alert) *TokenJob {
	return &TokenJob{
		watcher: watcher,
		cfg:     cfg,
		alerts:  alerts,
	}
}

// Run executes a single check of the token TTL.
func (tj *TokenJob) Run(ctx context.Context) error {
	info, err := tj.watcher.LookupSelf(ctx)
	if err != nil {
		return fmt.Errorf("token job: %w", err)
	}

	switch {
	case info.TTL <= tj.cfg.CriticalThreshold:
		tj.alerts <- Alert{
			Level:   Critical,
			Path:    "auth/token/self",
			Message: fmt.Sprintf("token expires in %s (accessor: %s)", info.TTL.Round(time.Second), info.Accessor),
		}
	case info.TTL <= tj.cfg.WarnThreshold:
		tj.alerts <- Alert{
			Level:   Warning,
			Path:    "auth/token/self",
			Message: fmt.Sprintf("token expires in %s (accessor: %s)", info.TTL.Round(time.Second), info.Accessor),
		}
		if tj.cfg.AutoRenew && info.Renewable {
			if err := tj.watcher.RenewSelf(ctx, tj.cfg.RenewIncrement); err != nil {
				log.Printf("[warn] token auto-renew failed: %v", err)
			} else {
				log.Printf("[info] token renewed successfully")
			}
		}
	default:
		log.Printf("[info] token TTL healthy: %s", info.TTL.Round(time.Second))
	}

	return nil
}
