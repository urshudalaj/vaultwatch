package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newHAMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestCheckHA_ReturnsStatus(t *testing.T) {
	payload := HAStatus{
		Enabled:       true,
		Leader:        "https://vault-0:8200",
		LeaderCluster: "https://vault-0:8201",
		PerfStandby:   false,
	}
	srv := newHAMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := NewHAChecker(srv.URL, "test-token", nil)
	got, err := checker.CheckHA()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Enabled {
		t.Error("expected HA to be enabled")
	}
	if got.Leader != payload.Leader {
		t.Errorf("leader: got %q, want %q", got.Leader, payload.Leader)
	}
}

func TestCheckHA_ErrorOnBadStatus(t *testing.T) {
	srv := newHAMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := NewHAChecker(srv.URL, "test-token", nil)
	_, err := checker.CheckHA()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckHA_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := NewHAChecker(srv.URL, "test-token", nil)
	_, err := checker.CheckHA()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
