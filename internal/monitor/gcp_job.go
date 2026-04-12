package monitor

import (
	"fmt"
	"log"

	"github.com/your-org/vaultwatch/internal/vault"
)

// gcpRolesetGetter is the interface used by GCPJob to fetch roleset info.
type gcpRolesetGetter interface {
	GetRoleset(mount, roleset string) (*vault.GCPRoleInfo, error)
}

// GCPJobConfig holds the mount and roleset pairs to monitor.
type GCPJobConfig struct {
	Mount   string
	Roleset string
}

// GCPJob monitors GCP rolesets for missing TTL configuration.
type GCPJob struct {
	checker  gcpRolesetGetter
	targets  []GCPJobConfig
	notifier alertSink
}

// NewGCPJob creates a new GCPJob.
func NewGCPJob(checker gcpRolesetGetter, targets []GCPJobConfig, notifier alertSink) *GCPJob {
	return &GCPJob{checker: checker, targets: targets, notifier: notifier}
}

// Run evaluates each GCP roleset and emits alerts for missing TTL fields.
func (j *GCPJob) Run() {
	for _, t := range j.targets {
		info, err := j.checker.GetRoleset(t.Mount, t.Roleset)
		if err != nil {
			log.Printf("gcp_job: skipping %s/%s: %v", t.Mount, t.Roleset, err)
			continue
		}

		if info.TTL == "" {
			j.notifier.Send(Alert{
				Level:   Warning,
				Message: fmt.Sprintf("GCP roleset %s/%s has no TTL configured", t.Mount, t.Roleset),
			})
		}

		if info.MaxTTL == "" {
			j.notifier.Send(Alert{
				Level:   Warning,
				Message: fmt.Sprintf("GCP roleset %s/%s has no MaxTTL configured", t.Mount, t.Roleset),
			})
		}
	}
}
