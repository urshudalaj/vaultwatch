package monitor

import (
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// IdentityGroupJobConfig holds configuration for the identity group monitor job.
type IdentityGroupJobConfig struct {
	Checker         *vault.IdentityGroupChecker
	RequireMembers  bool
	RequirePolicies bool
}

// NewIdentityGroupJob returns a RunnerFunc that checks identity groups for
// missing members or policies and emits alerts accordingly.
func NewIdentityGroupJob(cfg IdentityGroupJobConfig) RunnerFunc {
	return func() ([]Alert, error) {
		ids, err := cfg.Checker.ListGroups()
		if err != nil {
			return nil, fmt.Errorf("identity group list: %w", err)
		}

		var alerts []Alert

		for _, id := range ids {
			info, err := cfg.Checker.GetGroup(id)
			if err != nil {
				// Non-fatal: log and continue.
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("identity group %s: lookup failed: %v", id, err),
				})
				continue
			}

			if cfg.RequireMembers && len(info.MemberEntityIDs) == 0 {
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("identity group %q (%s) has no member entities", info.Name, id),
				})
			}

			if cfg.RequirePolicies && len(info.Policies) == 0 {
				alerts = append(alerts, Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("identity group %q (%s) has no attached policies", info.Name, id),
				})
			}
		}

		return alerts, nil
	}
}
