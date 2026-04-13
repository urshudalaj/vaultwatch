package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// EGPGetter is the interface satisfied by vault.EGPChecker.
type EGPGetter interface {
	GetEGP(name string) (*vault.EGPPolicy, error)
}

// EGPJob checks that named EGP policies exist and have a hard enforcement level.
type EGPJob struct {
	checker     EGPGetter
	policyNames []string
	notify      func(Alert)
}

// NewEGPJob constructs an EGPJob for the supplied policy names.
func NewEGPJob(checker EGPGetter, policyNames []string, notify func(Alert)) *EGPJob {
	return &EGPJob{
		checker:     checker,
		policyNames: policyNames,
		notify:      notify,
	}
}

// Run evaluates each EGP policy and emits an alert when enforcement is not hard-mandatory.
func (j *EGPJob) Run(ctx context.Context) error {
	for _, name := range j.policyNames {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		policy, err := j.checker.GetEGP(name)
		if err != nil {
			j.notify(Alert{
				Level:   Critical,
				Message: fmt.Sprintf("EGP policy %q lookup failed: %v", name, err),
			})
			continue
		}

		if policy.EnforcementLevel != "hard-mandatory" {
			j.notify(Alert{
				Level: Warning,
				Message: fmt.Sprintf(
					"EGP policy %q has enforcement_level %q (expected hard-mandatory)",
					policy.Name, policy.EnforcementLevel,
				),
			})
		}
	}
	return nil
}
