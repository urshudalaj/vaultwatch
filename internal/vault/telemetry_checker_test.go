package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTelemetryMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestGetTelemetry_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"Counters": []map[string]interface{}{
			{"Name": "vault.core.handle_request", "Count": 42.0},
		},
		"Gauges": []map[string]interface{}{
			{"Name": "vault.runtime.num_goroutines", "Value": 18.0},
		},
	}
	srv := newTelemetryMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := NewTelemetryChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetTelemetry()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, ok := info.Counters["vault.core.handle_request"]; !ok || v != 42.0 {
		t.Errorf("expected counter 42, got %v", v)
	}
	if v, ok := info.Gauges["vault.runtime.num_goroutines"]; !ok || v != 18.0 {
		t.Errorf("expected gauge 18, got %v", v)
	}
}

func TestGetTelemetry_ErrorOnBadStatus(t *testing.T) {
	srv := newTelemetryMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := NewTelemetryChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.GetTelemetry()
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func TestGetTelemetry_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := NewTelemetryChecker(srv.URL, "token", srv.Client())
	_, err := checker.GetTelemetry()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
