package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// caChecker is the interface for checking PKI CA expiry.
type caChecker interface {
	CheckCA(mount string) (*vault.CAInfo, error)
}

// CAJob monitors PKI CA certificate expiry for configured mounts.
type CAJob struct {
	checker       caChecker
	mounts        []string
	warningWindow time.Duration
}

// NewCAJob creates a new CAJob.
func NewCAJob(checker caChecker, mounts []string, warningWindow time.Duration) *CAJob {
	if warningWindow == 0 {
		warningWindow = 30 * 24 * time.Hour
	}
	return &CAJob{
		checker:       checker,
		mounts:        mounts,
		warningWindow: warningWindow,
	}
}

// Run checks each PKI mount and returns alerts for CAs expiring within the warning window.
func (j *CAJob) Run(_ context.Context) ([]Alert, error) {
	var alerts []Alert
	now := time.Now()

	for _, mount := range j.mounts {
		info, err := j.checker.CheckCA(mount)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("ca_job: error checking mount %s: %v", mount, err),
			})
			continue
		}

		remaining := info.Expiration.Sub(now)
		if remaining <= 0 {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("ca_job: CA cert on mount %s has expired", mount),
			})
		} else if remaining <= j.warningWindow {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("ca_job: CA cert on mount %s expires in %s", mount, formatDuration(remaining)),
			})
		}
	}

	return alerts, nil
}
