package monitor

import (
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubSSHChecker struct {
	roles map[string]*vault.SSHRoleInfo
	err   error
}

func (s *stubSSHChecker) GetRole(mount, role string) (*vault.SSHRoleInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	key := mount + "/" + role
	if info, ok := s.roles[key]; ok {
		return info, nil
	}
	return nil, errors.New("not found")
}

func sshJobWithStub(stub *stubSSHChecker, mounts, roles []string) (*SSHJob, *[]Alert) {
	var collected []Alert
	job := NewSSHJob(stub, SSHJobConfig{Mounts: mounts, Roles: roles}, func(a Alert) {
		collected = append(collected, a)
	})
	return job, &collected
}

func TestSSHJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	stub := &stubSSHChecker{
		roles: map[string]*vault.SSHRoleInfo{
			"ssh/admin": {Mount: "ssh", Role: "admin", KeyType: "ca", TTL: "30m", MaxTTL: "1h"},
		},
	}
	job, alerts := sshJobWithStub(stub, []string{"ssh"}, []string{"admin"})
	job.Run()
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(*alerts))
	}
}

func TestSSHJob_AlertWhenTTLMissing(t *testing.T) {
	stub := &stubSSHChecker{
		roles: map[string]*vault.SSHRoleInfo{
			"ssh/dev": {Mount: "ssh", Role: "dev", KeyType: "ca", TTL: "", MaxTTL: "2h"},
		},
	}
	job, alerts := sshJobWithStub(stub, []string{"ssh"}, []string{"dev"})
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != LevelWarning {
		t.Errorf("expected warning, got %s", (*alerts)[0].Level)
	}
}

func TestSSHJob_AlertWhenMaxTTLMissing(t *testing.T) {
	stub := &stubSSHChecker{
		roles: map[string]*vault.SSHRoleInfo{
			"ssh/ops": {Mount: "ssh", Role: "ops", KeyType: "ca", TTL: "1h", MaxTTL: ""},
		},
	}
	job, alerts := sshJobWithStub(stub, []string{"ssh"}, []string{"ops"})
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
}

func TestSSHJob_SkipsOnCheckerError(t *testing.T) {
	stub := &stubSSHChecker{err: errors.New("vault unavailable")}
	job, alerts := sshJobWithStub(stub, []string{"ssh"}, []string{"admin"})
	job.Run()
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts on checker error, got %d", len(*alerts))
	}
}
