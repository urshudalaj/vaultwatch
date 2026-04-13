package monitor

import (
	"context"
	"fmt"
)

// RADIUSRoleGetter retrieves a RADIUS role by mount and role name.
type RADIUSRoleGetter interface {
	GetRADIUSRole(mount, role string) (interface{ GetTTL() string; GetMaxTTL() string }, error)
}

// radiusRoleInfo is a local adapter so we can use the vault type without importing it.
type radiusRoleInfo struct {
	TTL    string
	MaxTTL string
}

func (r *radiusRoleInfo) GetTTL() string    { return r.TTL }
func (r *radiusRoleInfo) GetMaxTTL() string { return r.MaxTTL }

// RADIUSRoleSource is satisfied by vault.RADIUSChecker.
type RADIUSRoleSource interface {
	GetRADIUSRole(mount, role string) (*struct {
		Policies []string
		TTL      string
		MaxTTL   string
	}, error)
}

// RADIUSJobChecker is the minimal interface used by NewRADIUSJob.
type RADIUSJobChecker interface {
	GetRADIUSRoleTTLs(mount, role string) (ttl, maxTTL string, err error)
}

// RADIUSJob monitors a RADIUS auth role for missing TTL configuration.
type RADIUSJob struct {
	checker RADIUSJobChecker
	mount   string
	role    string
}

// NewRADIUSJob creates a job that checks a RADIUS role for TTL configuration.
func NewRADIUSJob(checker RADIUSJobChecker, mount, role string) *RADIUSJob {
	return &RADIUSJob{checker: checker, mount: mount, role: role}
}

// Run executes the RADIUS role TTL check and returns any alerts.
func (j *RADIUSJob) Run(_ context.Context) ([]Alert, error) {
	ttl, maxTTL, err := j.checker.GetRADIUSRoleTTLs(j.mount, j.role)
	if err != nil {
		return nil, fmt.Errorf("radius job: %w", err)
	}

	var alerts []Alert
	if ttl == "" || ttl == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("RADIUS role %s/%s has no TTL configured", j.mount, j.role),
		})
	}
	if maxTTL == "" || maxTTL == "0" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("RADIUS role %s/%s has no max_ttl configured", j.mount, j.role),
		})
	}
	return alerts, nil
}
