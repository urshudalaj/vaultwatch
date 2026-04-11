package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newRaftMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestCheckRaft_ReturnsStatus(t *testing.T) {
	payload := vault.RaftStatus{
		Healthy:                    true,
		OptimisticFailureTolerance: 1,
		Servers: map[string]vault.RaftServer{
			"node1": {ID: "node1", Name: "node1", Status: "leader", Leader: true, Voter: true, Healthy: true},
		},
	}
	srv := newRaftMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "test-token", nil)
	got, err := checker.CheckRaft(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Healthy {
		t.Error("expected healthy=true")
	}
	if len(got.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(got.Servers))
	}
}

func TestCheckRaft_ErrorOnBadStatus(t *testing.T) {
	srv := newRaftMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "bad-token", nil)
	_, err := checker.CheckRaft(context.Background())
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func TestCheckRaft_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer srv.Close()

	checker := vault.NewRaftChecker(srv.URL, "token", nil)
	_, err := checker.CheckRaft(context.Background())
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}
}
