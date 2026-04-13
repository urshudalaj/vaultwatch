package monitor

import (
	"context"
	"fmt"
)

// sentinelLister abstracts EGP/RGP listing for testability.
type sentinelLister interface {
	ListEGPs(ctx context.Context) ([]string, error)
	ListRGPs(ctx context.Context) ([]string, error)
}

// SentinelJob checks that at least one EGP and one RGP are configured in
// Vault, alerting when either list is empty.
type SentinelJob struct {
	lister sentinelLister
}

// NewSentinelJob creates a SentinelJob using the provided lister.
func NewSentinelJob(lister sentinelLister) *SentinelJob {
	return &SentinelJob{lister: lister}
}

// Run performs the sentinel policy check and returns any alerts.
func (j *SentinelJob) Run(ctx context.Context) ([]Alert, error) {
	var alerts []Alert

	egps, err := j.lister.ListEGPs(ctx)
	if err != nil {
		alerts = append(alerts, Alert{
			Level:   Critical,
			Message: fmt.Sprintf("sentinel: failed to list EGPs: %v", err),
		})
	} else if len(egps) == 0 {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: "sentinel: no Endpoint Governing Policies (EGPs) configured",
		})
	}

	rgps, err := j.lister.ListRGPs(ctx)
	if err != nil {
		alerts = append(alerts, Alert{
			Level:   Critical,
			Message: fmt.Sprintf("sentinel: failed to list RGPs: %v", err),
		})
	} else if len(rgps) == 0 {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: "sentinel: no Role Governing Policies (RGPs) configured",
		})
	}

	return alerts, nil
}
