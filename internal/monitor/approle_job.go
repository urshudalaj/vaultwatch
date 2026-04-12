package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// AppRoleTarget describes a single AppRole role to monitor.
type AppRoleTarget struct {
	Mount string
	Role  string
}

// appRoleGetter is the interface satisfied by vault.AppRoleChecker.
type appRoleGetter interface {
	GetRole(mount, role string) (*vault.AppRoleInfo, error)
}

// AppRoleJob checks AppRole roles for missing TTL configuration.
type AppRoleJob struct {
	checker appRoleGetter
	targets []AppRoleTarget
	send    func(Alert)
}

// NewAppRoleJob creates a job that monitors the provided AppRole targets.
func NewAppRoleJob(checker appRoleGetter, targets []AppRoleTarget, send func(Alert)) *AppRoleJob {
	return &AppRoleJob{checker: checker, targets: targets, send: send}
}

// Run inspects each AppRole target and emits alerts for misconfigured roles.
func (j *AppRoleJob) Run(_ context.Context) error {
	for _, t := range j.targets {
		info, err := j.checker.GetRole(t.Mount, t.Role)
		if err != nil {
			j.send(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("approle: failed to read role %s/%s: %v", t.Mount, t.Role, err),
			})
			continue
		}

		if info.TokenTTL == "" || info.TokenTTL == "0" {
			j.send(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("approle: role %s/%s has no token_ttl configured", t.Mount, t.Role),
			})
		}
		if info.TokenMaxTTL == "" || info.TokenMaxTTL == "0" {
			j.send(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("approle: role %s/%s has no token_max_ttl configured", t.Mount, t.Role),
			})
		}
		if !info.Enabled {
			j.send(Alert{
				Level:   LevelCritical,
				Message: fmt.Sprintf("approle: role %s/%s has bind_secret_id disabled", t.Mount, t.Role),
			})
		}
	}
	return nil
}
