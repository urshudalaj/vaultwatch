package monitor

import (
	"context"
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// AuditDeviceLister is the interface satisfied by vault.AuditChecker.
type AuditDeviceLister interface {
	ListAuditDevices(ctx context.Context) ([]vault.AuditDevice, error)
}

// AuditJob checks whether Vault has at least one audit device enabled
// and emits a critical alert if none are found.
type AuditJob struct {
	lister   AuditDeviceLister
	notifier AlertSender
}

// NewAuditJob creates an AuditJob with the given lister and notifier.
func NewAuditJob(lister AuditDeviceLister, notifier AlertSender) *AuditJob {
	return &AuditJob{lister: lister, notifier: notifier}
}

// Run performs the audit device check and sends an alert if no devices are configured.
func (j *AuditJob) Run(ctx context.Context) {
	devices, err := j.lister.ListAuditDevices(ctx)
	if err != nil {
		log.Printf("audit_job: failed to list audit devices: %v", err)
		return
	}

	if len(devices) == 0 {
		alert := Alert{
			Level:   Critical,
			Message: "no audit devices are enabled in Vault — audit logging is disabled",
			Path:    "sys/audit",
		}
		if err := j.notifier.Send(ctx, alert); err != nil {
			log.Printf("audit_job: send alert: %v", err)
		}
		return
	}

	log.Printf("audit_job: %d audit device(s) active: %s", len(devices), auditPaths(devices))
}

func auditPaths(devices []vault.AuditDevice) string {
	paths := ""
	for i, d := range devices {
		if i > 0 {
			paths += ", "
		}
		paths += fmt.Sprintf("%s(%s)", d.Path, d.Type)
	}
	return paths
}
