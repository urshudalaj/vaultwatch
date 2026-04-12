package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newRaftMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestCheckRaft_ReturnsStatus(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"leader_id":        "node-1",
			"applied_index":    uint64(42),
			"commit_index":     uint64(42),
			"num_peers":        3,
			"protocol_version": 3,
		},
	}
	srv := newRaftMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "test-token", nil)
	status, err := checker.CheckRaft()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.LeaderID != "node-1" {
		t.Errorf("expected leader_id node-1, got %s", status.LeaderID)
	}
	if status.NumPeers != 3 {
		t.Errorf("expected 3 peers, got %d", status.NumPeers)
	}
}

func TestCheckRaft_ErrorOnBadStatus(t *testing.T) {
	srv := newRaftMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "bad-token", nil)
	_, err := checker.CheckRaft()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckRaft_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "token", nil)
	_, err := checker.CheckRaft()
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
