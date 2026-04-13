package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// UserpassRoleTarget identifies a userpass user to monitor.
type UserpassRoleTarget struct {
	Mount    string
	Username string
}

// userpassChecker is the interface satisfied by vault.UserpassChecker.
type userpassChecker interface {
	GetUserpassRole(mount, username string) (*vault.UserpassRole, error)
}

// UserpassJob checks userpass roles for missing or zero TTL configuration.
type UserpassJob struct {
	checker userpassChecker
	targets []UserpassRoleTarget
	alerts  chan<- Alert
}

// NewUserpassJob creates a UserpassJob for the given targets.
func NewUserpassJob(checker userpassChecker, targets []UserpassRoleTarget, alerts chan<- Alert) *UserpassJob {
	return &UserpassJob{checker: checker, targets: targets, alerts: alerts}
}

// Run executes the userpass role check for all configured targets.
func (j *UserpassJob) Run(ctx context.Context) error {
	for _, t := range j.targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		role, err := j.checker.GetUserpassRole(t.Mount, t.Username)
		if err != nil {
			continue
		}

		label := fmt.Sprintf("userpass/%s/%s", t.Mount, t.Username)

		if role.TokenTTL == "" || role.TokenTTL == "0" {
			j.alerts <- Alert{
				Level:   Warning,
				Message: fmt.Sprintf("%s: token_ttl is not configured", label),
			}
		}
		if role.TokenMaxTTL == "" || role.TokenMaxTTL == "0" {
			j.alerts <- Alert{
				Level:   Warning,
				Message: fmt.Sprintf("%s: token_max_ttl is not configured", label),
			}
		}
	}
	return nil
}
