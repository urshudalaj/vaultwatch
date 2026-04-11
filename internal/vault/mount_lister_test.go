package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newMountMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/mounts" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestListMounts_ReturnsMounts(t *testing.T) {
	body := map[string]interface{}{
		"secret/": map[string]string{
			"type":        "kv",
			"description": "key/value secrets",
			"accessor":    "kv_abc123",
		},
		"sys/": map[string]string{
			"type":        "system",
			"description": "system backend",
			"accessor":    "system_xyz",
		},
	}
	srv := newMountMockServer(t, http.StatusOK, body)
	defer srv.Close()

	lister := vault.NewMountLister(srv.URL, "test-token", srv.Client())
	mounts, err := lister.ListMounts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts["secret/"].Type != "kv" {
		t.Errorf("expected type kv, got %s", mounts["secret/"].Type)
	}
}

func TestListMounts_ErrorOnBadStatus(t *testing.T) {
	srv := newMountMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	lister := vault.NewMountLister(srv.URL, "bad-token", srv.Client())
	_, err := lister.ListMounts(context.Background())
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func TestListMounts_SkipsEntriesWithoutType(t *testing.T) {
	body := map[string]interface{}{
		"secret/": map[string]string{
			"type":        "kv",
			"description": "kv store",
			"accessor":    "kv_1",
		},
		"request_id": "some-uuid",
	}
	srv := newMountMockServer(t, http.StatusOK, body)
	defer srv.Close()

	lister := vault.NewMountLister(srv.URL, "test-token", srv.Client())
	mounts, err := lister.ListMounts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := mounts["secret/"]; !ok {
		t.Error("expected secret/ mount to be present")
	}
	if _, ok := mounts["request_id"]; ok {
		t.Error("expected request_id to be skipped (no type field)")
	}
}
