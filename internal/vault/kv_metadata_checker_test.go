package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newKVMetaMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"current_version":      3,
				"oldest_version":       1,
				"created_time":         "2024-01-01T00:00:00Z",
				"updated_time":         "2024-06-01T00:00:00Z",
				"max_versions":         10,
				"delete_version_after": "0s",
			},
		})
	}))
}

func TestGetMetadata_ReturnsInfo(t *testing.T) {
	srv := newKVMetaMockServer(t)
	defer srv.Close()
	c := vault.NewKVMetadataChecker(srv.URL, "test-token", srv.Client())
	meta, err := c.GetMetadata("secret", "myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.CurrentVersion != 3 {
		t.Errorf("expected current_version 3, got %d", meta.CurrentVersion)
	}
	if meta.MaxVersions != 10 {
		t.Errorf("expected max_versions 10, got %d", meta.MaxVersions)
	}
}

func TestGetMetadata_ErrorOnEmptyParams(t *testing.T) {
	c := vault.NewKVMetadataChecker("http://localhost", "token", nil)
	_, err := c.GetMetadata("", "path")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
}

func TestGetMetadata_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := vault.NewKVMetadataChecker(srv.URL, "token", srv.Client())
	_, err := c.GetMetadata("secret", "missing")
	if err == nil {
		t.Fatal("expected error on 404")
	}
}
