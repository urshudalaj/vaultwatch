package monitor_test

import (
	"context"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

// stubKVReader implements a minimal KV reader for testing.
type stubKVReader struct {
	keys   []string
	values map[string]map[string]interface{}
	err    error
}

func (s *stubKVReader) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if s.err != nil {
		return nil, s.err
	}
	if v, ok := s.values[path]; ok {
		return v, nil
	}
	return map[string]interface{}{}, nil
}

func (s *stubKVReader) ListKeys(ctx context.Context, path string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.keys, nil
}

func kvJobWithStub(reader *stubKVReader, paths []string) *monitor.KVJob {
	return monitor.NewKVJob(reader, paths)
}

func TestKVJob_NoAlertWhenSecretsPresent(t *testing.T) {
	reader := &stubKVReader{
		keys: []string{"secret/db", "secret/api"},
		values: map[string]map[string]interface{}{
			"secret/db":  {"password": "hunter2"},
			"secret/api": {"token": "abc123"},
		},
	}
	job := kvJobWithStub(reader, []string{"secret/"})

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestKVJob_AlertWhenSecretEmpty(t *testing.T) {
	reader := &stubKVReader{
		keys: []string{"secret/empty"},
		values: map[string]map[string]interface{}{
			"secret/empty": {},
		},
	}
	job := kvJobWithStub(reader, []string{"secret/"})

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected at least one alert for empty secret")
	}
}

func TestKVJob_AlertWhenNoKeys(t *testing.T) {
	reader := &stubKVReader{
		keys:   []string{},
		values: map[string]map[string]interface{}{},
	}
	job := kvJobWithStub(reader, []string{"secret/"})

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected alert when no keys found under path")
	}
}

func TestKVJob_SkipsAlertOnListError(t *testing.T) {
	reader := &stubKVReader{
		err: fmt.Errorf("permission denied"),
	}
	job := kvJobWithStub(reader, []string{"secret/"})

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Errors from the reader should be surfaced as alerts, not hard errors
	if len(alerts) == 0 {
		t.Error("expected an alert when list fails")
	}
}

func TestKVJob_AlertContainsPath(t *testing.T) {
	const watchedPath = "secret/myapp/"
	reader := &stubKVReader{
		keys:   []string{},
		values: map[string]map[string]interface{}{},
	}
	job := kvJobWithStub(reader, []string{watchedPath})

	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	found := false
	for _, a := range alerts {
		if contains(a.Message, watchedPath) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected alert message to reference path %q", watchedPath)
	}
}

// contains is a simple substring helper used across job tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		})())
}

// Ensure time import is used indirectly via test helpers.
var _ = time.Second
