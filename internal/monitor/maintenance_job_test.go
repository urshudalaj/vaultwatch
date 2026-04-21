package monitor_test

import (
	"context"
	"errors"
	"testing"

	"github.com/wernerstrydom/vaultwatch/internal/monitor"
	"github.com/wernerstrydom/vaultwatch/internal/vault"
)

type stubMaintenanceChecker struct {
	info *vault.MaintenanceInfo
	err  error
}

func (s *stubMaintenanceChecker) CheckMaintenance() (*vault.MaintenanceInfo, error) {
	return s.info, s.err
}

func maintenanceJobWithStub(info *vault.MaintenanceInfo, err error) *monitor.MaintenanceJob {
	return monitor.NewMaintenanceJob(&stubMaintenanceChecker{info: info, err: err})
}

func TestMaintenanceJob_NoAlertWhenDisabled(t *testing.T) {
	job := maintenanceJobWithStub(&vault.MaintenanceInfo{Enabled: false}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestMaintenanceJob_AlertWhenEnabled(t *testing.T) {
	job := maintenanceJobWithStub(&vault.MaintenanceInfo{
		Enabled: true,
		Message: "planned work",
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.LevelWarning {
		t.Errorf("expected LevelWarning, got %v", alerts[0].Level)
	}
}

func TestMaintenanceJob_AlertMessageContainsDetail(t *testing.T) {
	job := maintenanceJobWithStub(&vault.MaintenanceInfo{
		Enabled: true,
		Message: "disk replacement",
	}, nil)
	alerts, _ := job.Run(context.Background())
	if len(alerts) == 0 {
		t.Fatal("expected alert")
	}
	if alerts[0].Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestMaintenanceJob_ErrorOnCheckerFailure(t *testing.T) {
	job := maintenanceJobWithStub(nil, errors.New("connection refused"))
	_, err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
