package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubStepDownChecker struct {
	info *vault.StepDownInfo
	err  error
}

func (s *stubStepDownChecker) CheckLeaderSelf(_ context.Context) (*vault.StepDownInfo, error) {
	return s.info, s.err
}

func stepDownJobWithStub(stub *stubStepDownChecker) (*StepDownJob, chan Alert) {
	ch := make(chan Alert, 4)
	return NewStepDownJob(stub, ch), ch
}

func TestStepDownJob_NoAlertWhenLeader(t *testing.T) {
	stub := &stubStepDownChecker{
		info: &vault.StepDownInfo{
			ClusterID:   "abc",
			ClusterName: "vault",
			LeaderAddr:  "https://vault.example.com",
			IsSelf:      true,
		},
	}
	job, ch := stepDownJobWithStub(stub)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) != 0 {
		t.Errorf("expected no alerts, got %d", len(ch))
	}
}

func TestStepDownJob_AlertWhenNotLeader(t *testing.T) {
	stub := &stubStepDownChecker{
		info: &vault.StepDownInfo{
			ClusterID:   "abc",
			ClusterName: "vault",
			LeaderAddr:  "https://other.example.com",
			IsSelf:      false,
		},
	}
	job, ch := stepDownJobWithStub(stub)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(ch))
	}
	a := <-ch
	if a.Level != Critical {
		t.Errorf("expected Critical, got %v", a.Level)
	}
}

func TestStepDownJob_ErrorOnCheckerFailure(t *testing.T) {
	stub := &stubStepDownChecker{err: errors.New("connection refused")}
	job, ch := stepDownJobWithStub(stub)
	if err := job.Run(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(ch) != 0 {
		t.Errorf("expected no alerts on error, got %d", len(ch))
	}
}
