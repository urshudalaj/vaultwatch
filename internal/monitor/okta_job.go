package monitor

import (
	"context"
	"fmt"

	"github.com/your-org/vaultwatch/internal/vault"
)

// OktaRoleGetter is the interface satisfied by vault.OktaChecker.
type OktaRoleGetter interface {
	GetOktaRole(mount, role string) (*vault.OktaRole, error)
}

// OktaJobConfig holds the parameters for an OktaJob.
type OktaJobConfig struct {
	Mount string
	Role  string
}

// OktaJob checks Okta auth role TTL configuration and raises alerts when
// TTL or MaxTTL values are missing.
type OktaJob struct {
	checker OktaRoleGetter
	cfg     OktaJobConfig
}

// NewOktaJob creates a new OktaJob.
func NewOktaJob(checker OktaRoleGetter, cfg OktaJobConfig) *OktaJob {
	return &OktaJob{checker: checker, cfg: cfg}
}

// Run executes the Okta role check and returns any alerts.
func (j *OktaJob) Run(_ context.Context) ([]Alert, error) {
	role, err := j.checker.GetOktaRole(j.cfg.Mount, j.cfg.Role)
	if err != nil {
		return nil, fmt.Errorf("okta_job: %w", err)
	}

	var alerts []Alert

	if role.TTL == "" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("okta role %s/%s has no TTL configured", j.cfg.Mount, j.cfg.Role),
		})
	}

	if role.MaxTTL == "" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("okta role %s/%s has no MaxTTL configured", j.cfg.Mount, j.cfg.Role),
		})
	}

	return alerts, nil
}
