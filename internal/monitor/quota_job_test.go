package monitor

import (
	"context"
	"errors"
	"testing"
)

type stubQuotaLister struct {
	names []string
	err   error
}

func (s *stubQuotaLister) ListQuotas(_ context.Context) ([]string, error) {
	return s.names, s.err
}

func quotaJobWithStub(names []string, listerErr error) (*QuotaJob, *captureNotifier) {
	n := &captureNotifier{}
	j := NewQuotaJob(&stubQuotaLister{names: names, err: listerErr}, n)
	return j, n
}

func TestQuotaJob_NoAlertWhenQuotasPresent(t *testing.T) {
	job, notifier := quotaJobWithStub([]string{"global-limit", "api-limit"}, nil)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(notifier.alerts))
	}
}

func TestQuotaJob_AlertWhenNoQuotas(t *testing.T) {
	job, notifier := quotaJobWithStub([]string{}, nil)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
	if notifier.alerts[0].Level != LevelWarning {
		t.Errorf("expected warning level, got %s", notifier.alerts[0].Level)
	}
}

func TestQuotaJob_SkipsAlertOnListerError(t *testing.T) {
	job, notifier := quotaJobWithStub(nil, errors.New("permission denied"))
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 0 {
		t.Errorf("expected no alerts on lister error, got %d", len(notifier.alerts))
	}
}

func TestQuotaJob_NilNamesIsNoQuota(t *testing.T) {
	job, notifier := quotaJobWithStub(nil, nil)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert for nil names, got %d", len(notifier.alerts))
	}
}
