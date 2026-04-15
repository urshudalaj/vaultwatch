package monitor

import (
	"context"
	"fmt"
)

// RenewalChecker is the interface for checking lease renewal eligibility.
type RenewalChecker interface {
	CheckRenewal(leaseID string) (*RenewalInfo, error)
}

// RenewalInfo mirrors vault.RenewalInfo to avoid import cycles.
type RenewalInfo struct {
	LeaseID   string
	Renewable bool
	TTL       int
	MaxTTL    int
}

// RenewalTarget describes a lease to monitor for renewal eligibility.
type RenewalTarget struct {
	LeaseID    string
	MinTTL     int // alert if TTL drops below this threshold (seconds)
}

// RenewalJob monitors lease renewal eligibility and TTL thresholds.
type RenewalJob struct {
	checker RenewalChecker
	targets []RenewalTarget
}

// NewRenewalJob creates a new RenewalJob.
func NewRenewalJob(checker RenewalChecker, targets []RenewalTarget) *RenewalJob {
	return &RenewalJob{checker: checker, targets: targets}
}

// Run checks each target lease and returns alerts for non-renewable or low-TTL leases.
func (j *RenewalJob) Run(_ context.Context) ([]Alert, error) {
	var alerts []Alert

	for _, target := range j.targets {
		info, err := j.checker.CheckRenewal(target.LeaseID)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("renewal check failed for lease %q: %v", target.LeaseID, err),
			})
			continue
		}

		if !info.Renewable {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("lease %q is not renewable", info.LeaseID),
			})
		}

		if target.MinTTL > 0 && info.TTL < target.MinTTL {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("lease %q TTL %ds is below minimum threshold %ds", info.LeaseID, info.TTL, target.MinTTL),
			})
		}
	}

	return alerts, nil
}
