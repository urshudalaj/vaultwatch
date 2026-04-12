package monitor_test

import (
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/monitor"
	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubRaftChecker struct {
	status *vault.RaftStatus
	err    error
}

func (s *stubRaftChecker) CheckRaft() (*vault.RaftStatus, error) {
	return s.status, s.err
}

func raftJobWithStub(stub *stubRaftChecker, cfg monitor.RaftJobConfig) (*monitor.RaftJob, chan monitor.Alert) {
	ch := make(chan monitor.Alert, 4)
	return monitor.NewRaftJob(stub, cfg, ch), ch
}

func TestRaftJob_NoAlertWhenHealthy(t *testing.T) {
	stub := &stubRaftChecker{
		status: &vault.RaftStatus{LeaderID: "node-1", FSMPending: 0},
	}
	job, ch := raftJobWithStub(stub, monitor.RaftJobConfig{MaxFSMPending: 100})
	job.Run()
	if len(ch) != 0 {
		t.Errorf("expected no alerts, got %d", len(ch))
	}
}

func TestRaftJob_AlertWhenNoLeader(t *testing.T) {
	stub := &stubRaftChecker{
		status: &vault.RaftStatus{LeaderID: ""},
	}
	job, ch := raftJobWithStub(stub, monitor.RaftJobConfig{})
	job.Run()
	if len(ch) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(ch))
	}
	a := <-ch
	if a.Level != monitor.Critical {
		t.Errorf("expected Critical, got %v", a.Level)
	}
}

func TestRaftJob_AlertWhenFSMPendingExceedsThreshold(t *testing.T) {
	stub := &stubRaftChecker{
		status: &vault.RaftStatus{LeaderID: "node-1", FSMPending: 200},
	}
	job, ch := raftJobWithStub(stub, monitor.RaftJobConfig{MaxFSMPending: 50})
	job.Run()
	if len(ch) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(ch))
	}
	a := <-ch
	if a.Level != monitor.Warning {
		t.Errorf("expected Warning, got %v", a.Level)
	}
}

func TestRaftJob_SkipsAlertOnCheckerError(t *testing.T) {
	stub := &stubRaftChecker{err: errors.New("connection refused")}
	job, ch := raftJobWithStub(stub, monitor.RaftJobConfig{})
	job.Run()
	if len(ch) != 0 {
		t.Errorf("expected no alerts on error, got %d", len(ch))
	}
}
