package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCubbyholeAPIClient(base string) *http.Client {
	return &http.Client{}
}

func newCubbyholeMockServer(t *testing.T, path string, keys []string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": keys,
			},
		})
	}))
}

func TestListCubbyholeKeys_ReturnsKeys(t *testing.T) {
	expected := []string{"secret-a", "secret-b"}
	srv := newCubbyholeMockServer(t, "mypath", expected, http.StatusOK)
	defer srv.Close()

	checker := NewCubbyholeChecker(srv.Client(), srv.URL, "test-token")
	info, err := checker.ListKeys("mypath")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(info.Keys))
	}
	if info.Keys[0] != "secret-a" {
		t.Errorf("expected secret-a, got %s", info.Keys[0])
	}
}

func TestListCubbyholeKeys_ErrorOnEmptyPath(t *testing.T) {
	checker := NewCubbyholeChecker(http.DefaultClient, "http://localhost", "token")
	_, err := checker.ListKeys("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestListCubbyholeKeys_ErrorOnBadStatus(t *testing.T) {
	srv := newCubbyholeMockServer(t, "mypath", nil, http.StatusForbidden)
	defer srv.Close()

	checker := NewCubbyholeChecker(srv.Client(), srv.URL, "bad-token")
	_, err := checker.ListKeys("mypath")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
