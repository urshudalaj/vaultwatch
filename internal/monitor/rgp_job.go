package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// RGPGetter retrieves a single RGP policy by name.
type RGPGetter interface {
	GetRGP(name string) (*vault.RGPPolicy, error)
}

// RGPJob checks RGP policies for missing enforcement levels.
type RGPJob struct {
	checker    RGPGetter
	policyName string
}

// NewRGPJob creates a new RGPJob for the given policy name.
func NewRGPJob(checker RGPGetter, policyName string) *RGPJob {
	return &RGPJob{checker: checker, policyName: policyName}
}

// Run fetches the RGP policy and returns alerts for weak or missing configuration.
func (j *RGPJob) Run(ctx context.Context) ([]Alert, error) {
	policy, err := j.checker.GetRGP(j.policyName)
	if err != nil {
		return nil, fmt.Errorf("rgp_job: failed to get policy %q: %w", j.policyName, err)
	}

	var alerts []Alert

	if policy.EnforcementLevel == "" {
		alerts = append(alerts, Alert{
			Level:   Critical,
			Message: fmt.Sprintf("RGP policy %q has no enforcement level set", policy.Name),
		})
	}

	if policy.Policy == "" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("RGP policy %q has an empty policy body", policy.Name),
		})
	}

	if policy.EnforcementLevel == "advisory" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("RGP policy %q uses advisory enforcement (consider hard-mandatory)", policy.Name),
		})
	}

	return alerts, nil
}
