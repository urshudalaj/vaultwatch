package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// SecretLeaseTarget describes a lease to monitor.
type SecretLeaseTarget struct {
	LeaseID         string
	WarnBefore      time.Duration
	CriticalBefore  time.Duration
}

// SecretLeaseChecker is the interface satisfied by vault.SecretLeaseChecker.
type SecretLeaseChecker interface {
	CheckLease(leaseID string) (*vault.SecretLeaseInfo, error)
}

// SecretLeaseJob monitors a set of lease IDs and fires alerts when expiry is near.
type SecretLeaseJob struct {
	checker  SecretLeaseChecker
	targets  []SecretLeaseTarget
	onAlert  func(Alert)
}

// NewSecretLeaseJob constructs a SecretLeaseJob.
func NewSecretLeaseJob(checker SecretLeaseChecker, targets []SecretLeaseTarget, onAlert func(Alert)) *SecretLeaseJob {
	return &SecretLeaseJob{
		checker: checker,
		targets: targets,
		onAlert: onAlert,
	}
}

// Run evaluates all configured lease targets and emits alerts as needed.
func (j *SecretLeaseJob) Run(_ context.Context) error {
	for _, t := range j.targets {
		if t.LeaseID == "" {
			continue
		}
		info, err := j.checker.CheckLease(t.LeaseID)
		if err != nil {
			j.onAlert(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("secret_lease: failed to check lease %q: %v", t.LeaseID, err),
			})
			continue
		}

		if info.ExpireTime.IsZero() {
			continue
		}

		remaining := time.Until(info.ExpireTime)
		switch {
		case remaining <= 0:
			j.onAlert(Alert{
				Level:   LevelCritical,
				Message: fmt.Sprintf("secret_lease: lease %q has expired", t.LeaseID),
			})
		case remaining <= t.CriticalBefore:
			j.onAlert(Alert{
				Level:   LevelCritical,
				Message: fmt.Sprintf("secret_lease: lease %q expires in %s", t.LeaseID, remaining.Round(time.Second)),
			})
		case remaining <= t.WarnBefore:
			j.onAlert(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("secret_lease: lease %q expires in %s", t.LeaseID, remaining.Round(time.Second)),
			})
		}
	}
	return nil
}
