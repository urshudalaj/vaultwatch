package monitor

import (
	"context"
	"fmt"
	"log"
	"time"
)

// SecretScanner is the interface for scanning Vault paths.
type SecretScanner interface {
	ScanPath(ctx context.Context, path string) ([]string, error)
	ReadLeaseInfo(ctx context.Context, path string) (leaseID string, leaseDuration int, renewable bool, err error)
}

// ScanJob scans configured paths and produces alerts for expiring leases.
type ScanJob struct {
	scanner       SecretScanner
	paths         []string
	warningWindow time.Duration
	criticalWindow time.Duration
	alertCh       chan<- Alert
}

// NewScanJob creates a ScanJob that emits alerts to the provided channel.
func NewScanJob(scanner SecretScanner, paths []string, warning, critical time.Duration, alertCh chan<- Alert) *ScanJob {
	return &ScanJob{
		scanner:        scanner,
		paths:          paths,
		warningWindow:  warning,
		criticalWindow: critical,
		alertCh:        alertCh,
	}
}

// Run performs a single scan cycle over all configured paths.
func (j *ScanJob) Run(ctx context.Context) error {
	for _, basePath := range j.paths {
		leaves, err := j.scanner.ScanPath(ctx, basePath)
		if err != nil {
			log.Printf("[scan] error listing %q: %v", basePath, err)
			continue
		}
		for _, leaf := range leaves {
			leaseID, duration, _, err := j.scanner.ReadLeaseInfo(ctx, leaf)
			if err != nil {
				log.Printf("[scan] error reading %q: %v", leaf, err)
				continue
			}
			if leaseID == "" || duration <= 0 {
				continue
			}
			expiry := time.Now().Add(time.Duration(duration) * time.Second)
			lease := NewLease(leaseID, leaf, expiry)
			status := lease.Status(j.warningWindow, j.criticalWindow)
			if status == StatusOK {
				continue
			}
			alert := Alert{
				LeaseID:   leaseID,
				Path:      leaf,
				ExpiresAt: expiry,
				Status:    fmt.Sprintf("%s", status),
			}
			select {
			case j.alertCh <- alert:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
