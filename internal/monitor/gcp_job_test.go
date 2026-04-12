package monitor

import (
	"errors"
	"testing"

	"github.com/your-org/vaultwatch/internal/vault"
)

type stubGCPChecker struct {
	info *vault.GCPRoleInfo
	err  error
}

func (s *stubGCPChecker) GetRoleset(_, _ string) (*vault.GCPRoleInfo, error) {
	return s.info, s.err
}

func gcpJobWithStub(info *vault.GCPRoleInfo, err error) (*GCPJob, *recordingSink) {
	sink := &recordingSink{}
	targets := []GCPJobConfig{{Mount: "gcp", Roleset: "my-roleset"}}
	job := NewGCPJob(&stubGCPChecker{info: info, err: err}, targets, sink)
	return job, sink
}

func TestGCPJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	info := &vault.GCPRoleInfo{
		Name:   "my-roleset",
		TTL:    "1h",
		MaxTTL: "24h",
	}
	job, sink := gcpJobWithStub(info, nil)
	job.Run()
	if len(sink.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(sink.alerts))
	}
}

func TestGCPJob_AlertWhenTTLMissing(t *testing.T) {
	info := &vault.GCPRoleInfo{
		Name:   "my-roleset",
		TTL:    "",
		MaxTTL: "24h",
	}
	job, sink := gcpJobWithStub(info, nil)
	job.Run()
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if sink.alerts[0].Level != Warning {
		t.Errorf("expected Warning level")
	}
}

func TestGCPJob_AlertWhenMaxTTLMissing(t *testing.T) {
	info := &vault.GCPRoleInfo{
		Name:   "my-roleset",
		TTL:    "1h",
		MaxTTL: "",
	}
	job, sink := gcpJobWithStub(info, nil)
	job.Run()
	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
}

func TestGCPJob_AlertWhenBothTTLsMissing(t *testing.T) {
	info := &vault.GCPRoleInfo{Name: "my-roleset"}
	job, sink := gcpJobWithStub(info, nil)
	job.Run()
	if len(sink.alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(sink.alerts))
	}
}

func TestGCPJob_SkipsAlertOnCheckerError(t *testing.T) {
	job, sink := gcpJobWithStub(nil, errors.New("vault unavailable"))
	job.Run()
	if len(sink.alerts) != 0 {
		t.Errorf("expected no alerts on checker error, got %d", len(sink.alerts))
	}
}
