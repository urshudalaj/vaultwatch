package monitor

import (
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// JWTRoleGetter abstracts fetching a JWT/OIDC role.
type JWTRoleGetter interface {
	GetRole(mount, role string) (*vault.JWTRole, error)
}

// JWTJobConfig carries the parameters for a JWT monitor job.
type JWTJobConfig struct {
	Mount   string
	Role    string
	Checker JWTRoleGetter
}

// NewJWTJob returns a RunFunc that checks a JWT/OIDC role for missing TTL
// configuration and emits alerts accordingly.
func NewJWTJob(cfg JWTJobConfig) RunFunc {
	return func() ([]Alert, error) {
		role, err := cfg.Checker.GetRole(cfg.Mount, cfg.Role)
		if err != nil {
			return []Alert{{
				Level:   Critical,
				Message: fmt.Sprintf("jwt: failed to read role %s/%s: %v", cfg.Mount, cfg.Role, err),
			}}, nil
		}

		var alerts []Alert

		if role.TokenTTL == 0 {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("jwt: role %s/%s has no token_ttl configured", cfg.Mount, cfg.Role),
			})
		}

		if role.TokenMaxTTL == 0 {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("jwt: role %s/%s has no token_max_ttl configured", cfg.Mount, cfg.Role),
			})
		}

		if len(role.BoundAudiences) == 0 {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("jwt: role %s/%s has no bound_audiences configured", cfg.Mount, cfg.Role),
			})
		}

		return alerts, nil
	}
}
