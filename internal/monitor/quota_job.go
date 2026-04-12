package monitor

import (
	"context"
	"fmt"
	"log"
)

// QuotaLister lists all quota names from Vault.
type QuotaLister interface {
	ListQuotas(ctx context.Context) ([]string, error)
}

// QuotaJob checks whether any rate-limit quotas are configured in Vault
// and raises a warning alert when none are found (unprotected cluster).
type QuotaJob struct {
	lister   QuotaLister
	notifier AlertNotifier
}

// NewQuotaJob creates a QuotaJob with the given lister and notifier.
func NewQuotaJob(lister QuotaLister, notifier AlertNotifier) *QuotaJob {
	return &QuotaJob{lister: lister, notifier: notifier}
}

// Run executes the quota check and dispatches an alert if no quotas exist.
func (j *QuotaJob) Run(ctx context.Context) error {
	names, err := j.lister.ListQuotas(ctx)
	if err != nil {
		log.Printf("[quota_job] list error: %v", err)
		return nil // non-fatal; Vault may not have Enterprise quota support
	}

	if len(names) == 0 {
		alert := Alert{
			Level:   LevelWarning,
			Message: "no rate-limit quotas configured — Vault API is unprotected",
			Path:    "sys/quotas/rate-limit",
		}
		if err := j.notifier.Send(ctx, alert); err != nil {
			return fmt.Errorf("quota_job notify: %w", err)
		}
		return nil
	}

	log.Printf("[quota_job] %d quota(s) configured: %v", len(names), names)
	return nil
}
