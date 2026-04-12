package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newEntityMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/identity/entity/id":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"abc-123", "def-456"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/identity/entity/id/abc-123":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id": "abc-123", "name": "alice",
					"disabled": false, "policies": []string{"default"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newEntityAPIClient(t *testing.T, srv *httptest.Server) *vault.EntityChecker {
	t.Helper()
	return vault.NewEntityChecker(srv.URL, "test-token", srv.Client())
}

func TestListEntities_ReturnsIDs(t *testing.T) {
	srv := newEntityMockServer(t)
	defer srv.Close()
	ec := newEntityAPIClient(t, srv)

	ids, err := ec.ListEntities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}

func TestGetEntity_ReturnsInfo(t *testing.T) {
	srv := newEntityMockServer(t)
	defer srv.Close()
	ec := newEntityAPIClient(t, srv)

	info, err := ec.GetEntity("abc-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "alice" {
		t.Errorf("expected name alice, got %s", info.Name)
	}
	if info.Disabled {
		t.Error("expected entity to be enabled")
	}
}

func TestGetEntity_ErrorOnEmptyID(t *testing.T) {
	srv := newEntityMockServer(t)
	defer srv.Close()
	ec := newEntityAPIClient(t, srv)

	_, err := ec.GetEntity("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestListEntities_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	ec := vault.NewEntityChecker(srv.URL, "bad-token", srv.Client())

	_, err := ec.ListEntities()
	if err == nil {
		t.Fatal("expected error on forbidden status")
	}
}
