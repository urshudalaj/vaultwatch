package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type stubACLChecker struct {
	info *ACLInfo
	err  error
}

func (s *stubACLChecker) LookupAccessor(_ string) (*ACLInfo, error) {
	return s.info, s.err
}

func aclJobWithStub(info *ACLInfo, err error, accessors []string) (*ACLJob, *capturingNotifier) {
	checker := &stubACLChecker{info: info, err: err}
	n := &capturingNotifier{}
	job := NewACLJob(checker, accessors, n, 24*time.Hour)
	return job, n
}

func TestACLJob_NoAlertWhenPoliciesPresent(t *testing.T) {
	info := &ACLInfo{
		Accessor:    "abc",
		DisplayName: "svc-token",
		Policies:    []string{"default"},
		ExpireTime:  time.Now().Add(48 * time.Hour).Format(time.RFC3339),
	}
	job, n := aclJobWithStub(info, nil, []string{"abc"})
	_ = job.Run(context.Background())
	if len(n.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(n.alerts))
	}
}

func TestACLJob_AlertWhenNoPolicies(t *testing.T) {
	info := &ACLInfo{
		Accessor:    "abc",
		DisplayName: "svc-token",
		Policies:    []string{},
		ExpireTime:  time.Now().Add(48 * time.Hour).Format(time.RFC3339),
	}
	job, n := aclJobWithStub(info, nil, []string{"abc"})
	_ = job.Run(context.Background())
	if len(n.alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(n.alerts))
	}
}

func TestACLJob_AlertWhenExpiringSoon(t *testing.T) {
	info := &ACLInfo{
		Accessor:    "xyz",
		DisplayName: "expiring-token",
		Policies:    []string{"default"},
		ExpireTime:  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}
	job, n := aclJobWithStub(info, nil, []string{"xyz"})
	_ = job.Run(context.Background())
	if len(n.alerts) != 1 {
		t.Errorf("expected 1 alert for expiring token, got %d", len(n.alerts))
	}
}

func TestACLJob_SkipsOnCheckerError(t *testing.T) {
	job, n := aclJobWithStub(nil, fmt.Errorf("lookup failed"), []string{"bad"})
	_ = job.Run(context.Background())
	if len(n.alerts) != 0 {
		t.Errorf("expected no alerts on error, got %d", len(n.alerts))
	}
}
