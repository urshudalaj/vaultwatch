package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGitHubMockServer(t *testing.T, role GitHubRole, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": role})
	}))
}

func newGitHubAPIClient(t *testing.T, srv *httptest.Server) *GitHubChecker {
	t.Helper()
	return NewGitHubChecker(srv.URL, "test-token", srv.Client())
}

func TestGetGitHubConfig_ReturnsInfo(t *testing.T) {
	want := GitHubRole{
		Organization: "acme",
		Teams:        []string{"devops"},
		Policies:     []string{"default"},
		TTL:          "1h",
		MaxTTL:       "24h",
	}
	srv := newGitHubMockServer(t, want, http.StatusOK)
	defer srv.Close()
	c := newGitHubAPIClient(t, srv)
	got, err := c.GetConfig("github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Organization != want.Organization {
		t.Errorf("org: got %q, want %q", got.Organization, want.Organization)
	}
	if got.TTL != want.TTL {
		t.Errorf("ttl: got %q, want %q", got.TTL, want.TTL)
	}
}

func TestGetGitHubConfig_ErrorOnEmptyMount(t *testing.T) {
	c := NewGitHubChecker("http://localhost", "tok", nil)
	_, err := c.GetConfig("")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
}

func TestGetGitHubConfig_ErrorOnBadStatus(t *testing.T) {
	srv := newGitHubMockServer(t, GitHubRole{}, http.StatusForbidden)
	defer srv.Close()
	c := newGitHubAPIClient(t, srv)
	_, err := c.GetConfig("github")
	if err == nil {
		t.Fatal("expected error on bad status")
	}
}
