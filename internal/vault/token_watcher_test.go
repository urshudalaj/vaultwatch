package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func newTokenMockServer(t *testing.T, ttl float64, renewable bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			payload := map[string]interface{}{
				"data": map[string]interface{}{
					"accessor":  "test-accessor",
					"ttl":       ttl,
					"renewable": renewable,
					"policies":  []interface{}{"default", "read-secrets"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(payload)
		case "/v1/auth/token/renew-self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"auth": map[string]interface{}{}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func newTokenAPIClient(t *testing.T, srv *httptest.Server) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	client.SetToken("test-token")
	return client
}

func TestLookupSelf_ReturnsTokenInfo(t *testing.T) {
	srv := newTokenMockServer(t, 3600.0, true)
	defer srv.Close()

	client := newTokenAPIClient(t, srv)
	watcher := NewTokenWatcher(client)

	info, err := watcher.LookupSelf(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Accessor != "test-accessor" {
		t.Errorf("expected accessor 'test-accessor', got %q", info.Accessor)
	}
	if !info.Renewable {
		t.Error("expected token to be renewable")
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
	if info.TTL.Seconds() != 3600 {
		t.Errorf("expected TTL 3600s, got %v", info.TTL)
	}
}

func TestRenewSelf_Success(t *testing.T) {
	srv := newTokenMockServer(t, 3600.0, true)
	defer srv.Close()

	client := newTokenAPIClient(t, srv)
	watcher := NewTokenWatcher(client)

	if err := watcher.RenewSelf(context.Background(), 3600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
