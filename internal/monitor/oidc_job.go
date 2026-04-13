package monitor

import (
	"context"
	"fmt"

	"github.com/subtlepseudonym/vaultwatch/internal/vault"
)

// OIDCRoleGetter is the interface used by OIDCJob to retrieve role info.
type OIDCRoleGetter interface {
	GetOIDCRole(mount, role string) (*vault.OIDCRole, error)
}

// OIDCJobConfig holds the parameters for a single OIDC role check.
type OIDCJobConfig struct {
	Mount string
	Role  string
}

// OIDCJob checks OIDC roles for missing or zero TTL configuration.
type OIDCJob struct {
	checker OIDCRoleGetter
	configs []OIDCJobConfig
}

// NewOIDCJob creates a new OIDCJob.
func NewOIDCJob(checker OIDCRoleGetter, configs []OIDCJobConfig) *OIDCJob {
	return &OIDCJob{checker: checker, configs: configs}
}

// Run checks each configured OIDC role and returns alerts for misconfigured roles.
func (j *OIDCJob) Run(_ context.Context) ([]Alert, error) {
	var alerts []Alert
	for _, cfg := range j.configs {
		role, err := j.checker.GetOIDCRole(cfg.Mount, cfg.Role)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("oidc_job: failed to read role %s/%s: %v", cfg.Mount, cfg.Role, err),
			})
			continue
		}
		if role.TTL == "" || role.TTL == "0" {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("oidc_job: role %s/%s has no TTL configured", cfg.Mount, cfg.Role),
			})
		}
		if role.MaxTTL == "" || role.MaxTTL == "0" {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("oidc_job: role %s/%s has no MaxTTL configured", cfg.Mount, cfg.Role),
			})
		}
		if role.UserClaim == "" {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("oidc_job: role %s/%s has no user_claim configured", cfg.Mount, cfg.Role),
			})
		}
	}
	return alerts, nil
}
