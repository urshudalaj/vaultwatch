package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/user/vaultwatch/internal/vault"
)

type stubSecretVersionChecker struct {
	info *vault.SecretVersionInfo
	err  error
}

func (s *stubSecretVersionChecker) GetSecretVersionInfo(_, _ string) (*vault.SecretVersionInfo, error) {
	return s.info, s.err
}

func secretVersionJobWithStub(info *vault.SecretVersionInfo, err error, targets []SecretVersionTarget) *SecretVersionJob {
	return NewSecretVersionJob(&stubSecretVersionChecker{info: info, err: err}, targets)
}

func TestSecretVersionJob_NoAlertWhenHealthy(t *testing.T) {
	info := &vault.SecretVersionInfo{
		Path: "myapp/db", CurrentVersion: 3, OldestVersion: 1, MaxVersions: 10, VersionCount: 3,
	}
	targets := []SecretVersionTarget{{Mount: "secret", Path: "myapp/db", MaxVersions: 5, MinVersionDrift: 5}}
	job := secretVersionJobWithStub(info, nil, targets)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestSecretVersionJob_AlertWhenMaxVersionsBelowThreshold(t *testing.T) {
	info := &vault.SecretVersionInfo{
		Path: "myapp/db", CurrentVersion: 2, OldestVersion: 1, MaxVersions: 3, VersionCount: 2,
	}
	targets := []SecretVersionTarget{{Mount: "secret", Path: "myapp/db", MaxVersions: 10}}
	job := secretVersionJobWithStub(info, nil, targets)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestSecretVersionJob_AlertWhenVersionDriftExceedsThreshold(t *testing.T) {
	info := &vault.SecretVersionInfo{
		Path: "myapp/db", CurrentVersion: 20, OldestVersion: 1, MaxVersions: 20, VersionCount: 20,
	}
	targets := []SecretVersionTarget{{Mount: "secret", Path: "myapp/db", MinVersionDrift: 10}}
	job := secretVersionJobWithStub(info, nil, targets)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestSecretVersionJob_AlertOnCheckerError(t *testing.T) {
	targets := []SecretVersionTarget{{Mount: "secret", Path: "myapp/db"}}
	job := secretVersionJobWithStub(nil, errors.New("vault unreachable"), targets)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %v", alerts[0].Level)
	}
}
