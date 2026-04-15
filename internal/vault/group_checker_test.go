package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGroupMockServer(t *testing.T, id string, info GroupInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/identity/group/id/"+id {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": info})
	}))
}

func newGroupAPIClient(srv *httptest.Server) *GroupChecker {
	return NewGroupChecker(srv.Client(), srv.URL, "test-token")
}

func TestGetGroup_ReturnsInfo(t *testing.T) {
	want := GroupInfo{
		ID:       "abc-123",
		Name:     "ops-team",
		Type:     "internal",
		Policies: []string{"default", "ops"},
		Disabled: false,
	}
	srv := newGroupMockServer(t, "abc-123", want)
	defer srv.Close()

	c := newGroupAPIClient(srv)
	got, err := c.GetGroup("abc-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != want.Name {
		t.Errorf("name: got %q, want %q", got.Name, want.Name)
	}
	if len(got.Policies) != 2 {
		t.Errorf("policies: got %d, want 2", len(got.Policies))


func TestGetGroup_ErrorOnEmptyID(t *testing.T) {
	c := NewGroupChecker(http://localhost", "tok")
	_, err := c.GetGroup("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestGetGroup_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newGroupAPIClient(srv)
	_, err := c.GetGroup("some-id")
	if err == nil {
		t.Fatal("expected error on bad status")
	}
}
