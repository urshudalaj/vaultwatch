package monitor

import (
	"context"
	"fmt"

	"github.com/wernerstrydom/vaultwatch/internal/vault"
)

// maintenanceChecker is the interface satisfied by vault.MaintenanceChecker.
type maintenanceChecker interface {
	CheckMaintenance() (*vault.MaintenanceInfo, error)
}

// MaintenanceJob checks whether Vault is in maintenance mode and raises an
// alert when it is.
type MaintenanceJob struct {
	checker maintenanceChecker
}

// NewMaintenanceJob creates a new MaintenanceJob.
func NewMaintenanceJob(checker maintenanceChecker) *MaintenanceJob {
	return &MaintenanceJob{checker: checker}
}

// Run executes the maintenance check and returns any alerts.
func (j *MaintenanceJob) Run(_ context.Context) ([]Alert, error) {
	info, err := j.checker.CheckMaintenance()
	if err != nil {
		return nil, fmt.Errorf("maintenance job: %w", err)
	}

	if !info.Enabled {
		return nil, nil
	}

	msg := "Vault is in maintenance mode"
	if info.Message != "" {
		msg = fmt.Sprintf("%s: %s", msg, info.Message)
	}

	return []Alert{
		{
			Level:   LevelWarning,
			Message: msg,
			Path:    "sys/maintenance",
		},
	}, nil
}
