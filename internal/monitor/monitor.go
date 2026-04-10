package monitor

import (
	"context"
	"log"
	"time"

	"github.com/user/vaultwatch/internal/config"
	"github.com/user/vaultwatch/internal/vault"
)

// Monitor polls Vault secret paths and emits alerts for expiring leases.
type Monitor struct {
	cfg    *config.Config
	client *vault.Client
	alerts chan Alert
}

// New creates a Monitor from the given config and Vault client.
func New(cfg *config.Config, client *vault.Client) *Monitor {
	return &Monitor{
		cfg:    cfg,
		client: client,
		alerts: make(chan Alert, 64),
	}
}

// Alerts returns a read-only channel of fired alerts.
func (m *Monitor) Alerts() <-chan Alert {
	return m.alerts
}

// Run starts the polling loop and blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(m.alerts)
			return
		case <-ticker.C:
			m.poll()
		}
	}
}

func (m *Monitor) poll() {
	warning := m.cfg.WarningThreshold
	for _, path := range m.cfg.SecretPaths {
		lease, err := m.client.ReadSecretLease(path)
		if err != nil {
			log.Printf("[monitor] error reading %s: %v", path, err)
			continue
		}
		switch lease.Status(warning) {
		case LeaseWarning:
			m.alerts <- Alert{Lease: lease, Level: AlertWarning}
		case LeaseExpired:
			m.alerts <- Alert{Lease: lease, Level: AlertCritical}
		}
	}
}
