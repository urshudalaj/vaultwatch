package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newIdentityGroupMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/group/id":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"group-id-1", "group-id-2"},
				},
			})
		case "/v1/identity/group/id/group-id-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":       "group-id-1",
					"name":     "admins",
					"type":     "internal",
					"policies": []string{"admin", "default"},
					"member_entity_ids": []string{"entity-1"},
				},
			})
		case "/v1/identity/group/id/group-id-empty":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":               "group-id-empty",
					"name":             "empty-group",
					"type":             "internal",
					"policies":         []string{},
					"member_entity_ids": []string{},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newIdentityGroupAPIClient(t *testing.T, srv *httptest.Server) *vault.IdentityGroupChecker {
	t.Helper()
	c, err := vault.NewIdentityGroupChecker(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewIdentityGroupChecker: %v", err)
	}
	return c
}

func TestListIdentityGroups_ReturnsIDs(t *testing.T) {
	srv := newIdentityGroupMockServer(t)
	defer srv.Close()
	c := newIdentityGroupAPIClient(t, srv)

	ids, err := c.ListGroups()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
}

func TestGetIdentityGroup_ReturnsInfo(t *testing.T) {
	srv := newIdentityGroupMockServer(t)
	defer srv.Close()
	c := newIdentityGroupAPIClient(t, srv)

	info, err := c.GetGroup("group-id-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "admins" {
		t.Errorf("expected name 'admins', got %q", info.Name)
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
}

func TestGetIdentityGroup_ErrorOnEmptyID(t *testing.T) {
	srv := newIdentityGroupMockServer(t)
	defer srv.Close()
	c := newIdentityGroupAPIClient(t, srv)

	_, err := c.GetGroup("")
	if err == nil {
		t.Fatal("expected error for empty ID, got nil")
	}
}

func TestGetIdentityGroup_EmptyMembersReturnsInfo(t *testing.T) {
	srv := newIdentityGroupMockServer(t)
	defer srv.Close()
	c := newIdentityGroupAPIClient(t, srv)

	info, err := c.GetGroup("group-id-empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.MemberEntityIDs) != 0 {
		t.Errorf("expected 0 members, got %d", len(info.MemberEntityIDs))
	}
}
