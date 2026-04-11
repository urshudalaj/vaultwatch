package monitor

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// PolicyWatcher defines the interface for fetching Vault policy data.
type PolicyWatcher interface {
	ListPolicies(ctx context.Context) ([]string, error)
	GetPolicy(ctx context.Context, name string) (*vault.PolicyInfo, error)
}

// PolicyJob checks whether sensitive policies contain overly broad rules.
type PolicyJob struct {
	watcher  PolicyWatcher
	alerter  Alerter
	banned   []string // rule fragments considered too permissive
}

// NewPolicyJob constructs a PolicyJob.
func NewPolicyJob(w PolicyWatcher, a Alerter, bannedFragments []string) *PolicyJob {
	return &PolicyJob{
		watcher: w,
		alerter: a,
		banned:  bannedFragments,
	}
}

// Run lists all policies and alerts on any that contain banned rule fragments.
func (j *PolicyJob) Run(ctx context.Context) error {
	names, err := j.watcher.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("policy job list: %w", err)
	}

	for _, name := range names {
		info, err := j.watcher.GetPolicy(ctx, name)
		if err != nil {
			log.Printf("[policy_job] skipping %q: %v", name, err)
			continue
		}

		for _, fragment := range j.banned {
			if strings.Contains(info.Rules, fragment) {
				j.alerter.Send(Alert{
					Level:   AlertWarning,
					Message: fmt.Sprintf("policy %q contains banned fragment %q", name, fragment),
				})
				break
			}
		}
	}
	return nil
}
