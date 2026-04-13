package monitor

import (
	"context"
	"fmt"
)

// SAMLRoleReader fetches SAML role configuration.
type SAMLRoleReader interface {
	GetSAMLRole(mount, role string) (interface{ GetTTL() string; GetMaxTTL() string }, error)
}

// samlRoleInfo is a minimal interface satisfied by vault.SAMLRole via adapter.
type samlRoleInfo struct {
	TTL    string
	MaxTTL string
}

func (r samlRoleInfo) GetTTL() string    { return r.TTL }
func (r samlRoleInfo) GetMaxTTL() string { return r.MaxTTL }

// SAMLRoleChecker is the subset of SAMLChecker used by SAMLJob.
type SAMLRoleChecker interface {
	GetSAMLRole(mount, role string) (*samlRoleResult, error)
}

type samlRoleResult struct {
	TTL    string
	MaxTTL string
}

// SAMLJob monitors SAML auth role TTL configuration.
type SAMLJob struct {
	checker interface {
		GetSAMLRole(mount, role string) (*samlRoleResult, error)
	}
	mount string
	role  string
}

// samlCheckerAdapter wraps vault.SAMLChecker to match the internal interface.
type samlCheckerAdapter struct {
	fn func(mount, role string) (*samlRoleResult, error)
}

func (a *samlCheckerAdapter) GetSAMLRole(mount, role string) (*samlRoleResult, error) {
	return a.fn(mount, role)
}

// NewSAMLJob creates a SAMLJob that checks TTL configuration for a SAML role.
func NewSAMLJob(mount, role string, fn func(mount, role string) (*samlRoleResult, error)) *SAMLJob {
	return &SAMLJob{
		checker: &samlCheckerAdapter{fn: fn},
		mount:   mount,
		role:    role,
	}
}

// Run checks the SAML role and returns alerts if TTL fields are missing.
func (j *SAMLJob) Run(ctx context.Context) ([]Alert, error) {
	info, err := j.checker.GetSAMLRole(j.mount, j.role)
	if err != nil {
		return nil, fmt.Errorf("saml_job: %w", err)
	}

	var alerts []Alert
	path := fmt.Sprintf("auth/%s/role/%s", j.mount, j.role)

	if info.TTL == "" || info.TTL == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("SAML role %q has no TTL configured", path),
			Path:    path,
		})
	}
	if info.MaxTTL == "" || info.MaxTTL == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("SAML role %q has no MaxTTL configured", path),
			Path:    path,
		})
	}
	return alerts, nil
}
