package monitor

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// tokenInfoProvider abstracts vault.TokenWatcher for testing.
type tokenInfoProvider interface {
	LookupSelf(ctx context.Context) (*vault.TokenInfo, error)
	RenewSelf(ctx context.Context, increment int) error
}

// runTokenJobLogic contains the core alert/renew logic, accepting an interface
// so it can be driven by a stub in tests or the real watcher in production.
func runTokenJobLogic(tj *TokenJob, provider tokenInfoProvider, ctx context.Context) error {
	info, err := provider.LookupSelf(ctx)
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
			if err := provider.RenewSelf(ctx, tj.cfg.RenewIncrement); err != nil {
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
