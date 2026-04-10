// Package scheduler provides periodic execution of vault secret monitoring.
package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/yourusername/vaultwatch/internal/monitor"
	"github.com/yourusername/vaultwatch/internal/notifier"
	"github.com/yourusername/vaultwatch/internal/reporter"
)

// Runner holds the dependencies needed to run periodic checks.
type Runner struct {
	monitor  *monitor.Monitor
	notifier *notifier.Notifier
	reporter *reporter.Reporter
	interval time.Duration
}

// New creates a new scheduler Runner.
func New(m *monitor.Monitor, n *notifier.Notifier, r *reporter.Reporter, interval time.Duration) *Runner {
	return &Runner{
		monitor:  m,
		notifier: n,
		reporter: r,
		interval: interval,
	}
}

// Run starts the scheduling loop, executing a check immediately and then
// on every tick of the configured interval. It blocks until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	log.Printf("scheduler: starting with interval %s", r.interval)
	r.runOnce(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.runOnce(ctx)
		case <-ctx.Done():
			log.Println("scheduler: shutting down")
			return
		}
	}
}

// runOnce performs a single monitoring cycle: collect alerts, notify, report.
func (r *Runner) runOnce(ctx context.Context) {
	alerts, err := r.monitor.Check(ctx)
	if err != nil {
		log.Printf("scheduler: monitor check error: %v", err)
		return
	}

	for _, a := range alerts {
		if err := r.notifier.Send(ctx, a); err != nil {
			log.Printf("scheduler: notify error for %s: %v", a.SecretPath, err)
		}
	}

	if err := r.reporter.Write(alerts); err != nil {
		log.Printf("scheduler: report error: %v", err)
	}
}
