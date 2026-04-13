package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// MFALister is the interface satisfied by vault.MFAChecker.
type MFALister interface {
	ListMFAMethods() ([]vault.MFAMethod, error)
}

// MFAJob checks that at least one MFA method is configured.
type MFAJob struct {
	lister MFALister
}

// NewMFAJob returns a new MFAJob.
func NewMFAJob(lister MFALister) *MFAJob {
	return &MFAJob{lister: lister}
}

// Run executes the MFA check and returns any alerts.
func (j *MFAJob) Run(_ context.Context) ([]Alert, error) {
	methods, err := j.lister.ListMFAMethods()
	if err != nil {
		return nil, fmt.Errorf("mfa_job: list methods: %w", err)
	}

	if len(methods) == 0 {
		return []Alert{
			{
				Level:   Critical,
				Message: "no MFA methods configured — access controls may be insufficient",
			},
		}, nil
	}

	var alerts []Alert
	for _, m := range methods {
		if m.Type == "" {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("MFA method %q has no type set", m.Name),
			})
		}
	}
	return alerts, nil
}
