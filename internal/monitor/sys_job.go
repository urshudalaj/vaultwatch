package monitor

import (
	"fmt"

	"github.com/watcher/vaultwatch/internal/vault"
)

// SysInfoProvider is satisfied by vault.SysChecker.
type SysInfoProvider interface {
	GetSysInfo() (*vault.SysInfo, error)
}

// SysJob checks that Vault system info is accessible and the cluster
// name and version are non-empty, emitting alerts when they are missing.
type SysJob struct {
	checker SysInfoProvider
}

// NewSysJob creates a SysJob with the provided SysInfoProvider.
func NewSysJob(checker SysInfoProvider) *SysJob {
	return &SysJob{checker: checker}
}

// Run fetches system info and returns alerts for any missing fields.
func (j *SysJob) Run() ([]Alert, error) {
	info, err := j.checker.GetSysInfo()
	if err != nil {
		return []Alert{{
			Level:   Critical,
			Message: fmt.Sprintf("sys job: failed to retrieve system info: %v", err),
		}}, nil
	}

	var alerts []Alert

	if info.ClusterName == "" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: "sys job: cluster_name is empty — Vault may not be fully initialised",
		})
	}

	if info.Version == "" {
		alerts = append(alerts, Alert{
			Level:   Warning,
			Message: "sys job: version string is empty — unable to verify Vault release",
		})
	}

	return alerts, nil
}
