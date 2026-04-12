package monitor

import (
	"fmt"
	"time"
)

// PKIRoleGetter retrieves PKI role configuration from Vault.
type PKIRoleGetter interface {
	GetRole(mount, role string) (*PKICertInfo, error)
}

// PKICertInfo mirrors vault.PKICertInfo to avoid import cycles.
type PKICertInfo struct {
	Mount          string
	Role           string
	MaxTTL         string
	TTL            string
	AllowedDomains []string
}

// PKIJobConfig holds the mount/role pairs to monitor.
type PKIJobConfig struct {
	Mount string
	Role  string
}

// PKIJob checks PKI roles for missing TTL configuration.
type PKIJob struct {
	checker PKIRoleGetter
	roles   []PKIJobConfig
	notify  func(Alert)
}

// NewPKIJob creates a PKIJob that monitors the given PKI roles.
func NewPKIJob(checker PKIRoleGetter, roles []PKIJobConfig, notify func(Alert)) *PKIJob {
	return &PKIJob{checker: checker, roles: roles, notify: notify}
}

// Run checks each configured PKI role and fires alerts for misconfigured TTLs.
func (j *PKIJob) Run() error {
	for _, r := range j.roles {
		info, err := j.checker.GetRole(r.Mount, r.Role)
		if err != nil {
			j.notify(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("pki: failed to read role %s/%s: %v", r.Mount, r.Role, err),
				Time:    time.Now(),
			})
			continue
		}
		if info.MaxTTL == "" || info.MaxTTL == "0" {
			j.notify(Alert{
				Level:   LevelCritical,
				Message: fmt.Sprintf("pki: role %s/%s has no max_ttl configured", r.Mount, r.Role),
				Time:    time.Now(),
			})
		}
		if info.TTL == "" || info.TTL == "0" {
			j.notify(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("pki: role %s/%s has no default ttl configured", r.Mount, r.Role),
				Time:    time.Now(),
			})
		}
	}
	return nil
}
