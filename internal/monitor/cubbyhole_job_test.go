package monitor_test

import (
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

type stubCubbyholeChecker struct {
	keys map[string][]string
	err  error
}

func (s *stubCubbyholeChecker) ListCubbyholeKeys(path string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.keys[path], nil
}

func cubbyholeJobWithStub(keys map[string][]string, paths []string, expected map[string][]string) *monitor.CubbyholeJob {
	return monitor.NewCubbyholeJob(&stubCubbyholeChecker{keys: keys}, paths, expected)
}

func TestCubbyholeJob_NoAlertWhenKeysPresent(t *testing.T) {
	keys := map[string][]string{
		"secret/myapp": {"api-key", "db-pass"},
	}
	expected := map[string][]string{
		"secret/myapp": {"api-key", "db-pass"},
	}
	job := cubbyholeJobWithStub(keys, []string{"secret/myapp"}, expected)
	alerts := job.Run()
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts, got %d: %v", len(alerts), alerts)
	}
}

func TestCubbyholeJob_AlertWhenNoKeys(t *testing.T) {
	keys := map[string][]string{
		"secret/empty": {},
	}
	job := cubbyholeJobWithStub(keys, []string{"secret/empty"}, nil)
	alerts := job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestCubbyholeJob_AlertWhenExpectedKeyMissing(t *testing.T) {
	keys := map[string][]string{
		"secret/myapp": {"api-key"},
	}
	expected := map[string][]string{
		"secret/myapp": {"api-key", "db-pass"},
	}
	job := cubbyholeJobWithStub(keys, []string{"secret/myapp"}, expected)
	alerts := job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.Warning {
		t.Errorf("expected Warning level, got %v", alerts[0].Level)
	}
}

func TestCubbyholeJob_AlertOnCheckerError(t *testing.T) {
	checker := &stubCubbyholeChecker{err: errors.New("permission denied")}
	job := monitor.NewCubbyholeJob(checker, []string{"secret/myapp"}, nil)
	alerts := job.Run()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != monitor.Critical {
		t.Errorf("expected Critical level, got %v", alerts[0].Level)
	}
}
