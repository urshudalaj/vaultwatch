package monitor_test

import (
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

type stubPKIChecker struct {
	info *monitor.PKICertInfo
	err  error
}

func (s *stubPKIChecker) GetRole(mount, role string) (*monitor.PKICertInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.info, nil
}

func pkiJobWithStub(checker monitor.PKIRoleGetter, roles []monitor.PKIJobConfig) ([]monitor.Alert, *monitor.PKIJob) {
	var alerts []monitor.Alert
	job := monitor.NewPKIJob(checker, roles, func(a monitor.Alert) {
		alerts = append(alerts, a)
	})
	return alerts, job
}

func TestPKIJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	checker := &stubPKIChecker{info: &monitor.PKICertInfo{
		Mount: "pki", Role: "web", MaxTTL: "8760h", TTL: "720h",
	}}
	roles := []monitor.PKIJobConfig{{Mount: "pki", Role: "web"}}
	alerts, job := pkiJobWithStub(checker, roles)
	if err := job.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestPKIJob_AlertWhenMaxTTLMissing(t *testing.T) {
	checker := &stubPKIChecker{info: &monitor.PKICertInfo{
		Mount: "pki", Role: "web", MaxTTL: "", TTL: "720h",
	}}
	roles := []monitor.PKIJobConfig{{Mount: "pki", Role: "web"}}
	alerts, job := pkiJobWithStub(checker, roles)
	_ = job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.LevelCritical {
		t.Errorf("expected critical alert, got %s", alerts[0].Level)
	}
}

func TestPKIJob_AlertWhenDefaultTTLMissing(t *testing.T) {
	checker := &stubPKIChecker{info: &monitor.PKICertInfo{
		Mount: "pki", Role: "web", MaxTTL: "8760h", TTL: "",
	}}
	roles := []monitor.PKIJobConfig{{Mount: "pki", Role: "web"}}
	alerts, job := pkiJobWithStub(checker, roles)
	_ = job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.LevelWarning {
		t.Errorf("expected warning alert, got %s", alerts[0].Level)
	}
}

func TestPKIJob_AlertOnCheckerError(t *testing.T) {
	checker := &stubPKIChecker{err: errors.New("vault unreachable")}
	roles := []monitor.PKIJobConfig{{Mount: "pki", Role: "web"}}
	alerts, job := pkiJobWithStub(checker, roles)
	_ = job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.LevelWarning {
		t.Errorf("expected warning alert, got %s", alerts[0].Level)
	}
}
