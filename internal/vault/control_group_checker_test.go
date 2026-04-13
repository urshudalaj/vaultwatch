package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newControlGroupMockServer(t *testing.T, approved bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/control-group/request" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":           "req-123",
				"request_path": "secret/data/foo",
				"approved":     approved,
				"request_entity": map[string]string{
					"id":   "entity-abc",
					"name": "alice",
				},
			},
		})
	}))
}

func TestCheckRequest_ReturnsInfo(t *testing.T) {
	srv := newControlGroupMockServer(t, true)
	defer srv.Close()

	checker := NewControlGroupChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.CheckRequest(context.Background(), "accessor-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ID != "req-123" {
		t.Errorf("expected id req-123, got %s", info.ID)
	}
	if !info.Approved {
		t.Error("expected approved=true")
	}
	if info.RequestEntity.Name != "alice" {
		t.Errorf("expected entity name alice, got %s", info.RequestEntity.Name)
	}
}

func TestCheckRequest_ErrorOnEmptyAccessor(t *testing.T) {
	checker := NewControlGroupChecker("http://localhost", "token", nil)
	_, err := checker.CheckRequest(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestCheckRequest_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	checker := NewControlGroupChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.CheckRequest(context.Background(), "some-accessor")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
