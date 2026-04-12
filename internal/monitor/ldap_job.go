package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// LDAPRoleGetter retrieves an LDAP role configuration.
type LDAPRoleGetter interface {
	GetRole(mount, role string) (*vault.LDAPRole, error)
}

// LDAPJobConfig holds the configuration for an LDAP monitor job.
type LDAPJobConfig struct {
	Mount string
	Role  string
}

// LDAPJob monitors LDAP secrets engine roles for missing TTL configuration.
type LDAPJob struct {
	checker LDAPRoleGetter
	cfg     LDAPJobConfig
}

// NewLDAPJob creates a new LDAPJob.
func NewLDAPJob(checker LDAPRoleGetter, cfg LDAPJobConfig) *LDAPJob {
	return &LDAPJob{checker: checker, cfg: cfg}
}

// Run checks the LDAP role and returns alerts for missing TTL fields.
func (j *LDAPJob) Run(_ context.Context) ([]Alert, error) {
	role, err := j.checker.GetRole(j.cfg.Mount, j.cfg.Role)
	if err != nil {
		return nil, fmt.Errorf("ldap job: %w", err)
	}

	var alerts []Alert

	if role.DefaultTTL == "" || role.DefaultTTL == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("LDAP role %q on mount %q has no default_ttl configured", j.cfg.Role, j.cfg.Mount),
		})
	}

	if role.MaxTTL == "" || role.MaxTTL == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("LDAP role %q on mount %q has no max_ttl configured", j.cfg.Role, j.cfg.Mount),
		})
	}

	return alerts, nil
}
