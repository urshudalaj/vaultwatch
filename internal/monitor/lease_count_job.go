package monitor

import (
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// LeaseCountThreshold is the default alert threshold for total lease count.
const LeaseCountThreshold = 10000

// leaseCountChecker is the interface used by LeaseCountJob.
type leaseCountChecker interface {
	GetLeaseCount() (*vault.LeaseCountInfo, error)
}

// LeaseCountJob checks whether the total Vault lease count exceeds a threshold.
type LeaseCountJob struct {
	checker   leaseCountChecker
	threshold int
}

// NewLeaseCountJob creates a LeaseCountJob with the given checker and threshold.
// If threshold is zero the default LeaseCountThreshold is used.
func NewLeaseCountJob(checker leaseCountChecker, threshold int) *LeaseCountJob {
	if threshold <= 0 {
		threshold = LeaseCountThreshold
	}
	return &LeaseCountJob{checker: checker, threshold: threshold}
}

// Run executes the lease count check and returns any alerts.
func (j *LeaseCountJob) Run() ([]Alert, error) {
	info, err := j.checker.GetLeaseCount()
	if err != nil {
		return nil, fmt.Errorf("lease count job: %w", err)
	}

	var alerts []Alert
	if info.LeaseCount >= j.threshold {
		alerts = append(alerts, Alert{
			Level:   Critical,
			Message: fmt.Sprintf("vault lease count %d meets or exceeds threshold %d", info.LeaseCount, j.threshold),
		})
	} else if info.LeaseCount >= j.threshold/2 {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: fmt.Sprintf("vault lease count %d is above 50%% of threshold %d", info.LeaseCount, j.threshold),
		})
	}
	return alerts, nil
}
