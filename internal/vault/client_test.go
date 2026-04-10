package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newMockVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"initialized": true,
			"sealed":      false,
			"standby":     false,
		})
	})

	mux.HandleFunc("/v1/secret/myapp/db", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"lease_id":       "secret/myapp/db/abc123",
			"lease_duration": 3600,
			"renewable":      true,
			"data": map[string]string{
				"password": "s3cr3t",
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestNewClient(t *testing.T) {
	_, err := NewClient("http://127.0.0.1:8200", "test-token")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestIsHealthy(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.IsHealthy(context.Background()); err != nil {
		t.Errorf("expected healthy vault, got error: %v", err)
	}
}

func TestReadSecret(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	info, err := client.ReadSecret(context.Background(), "secret/myapp/db")
	if err != nil {
		t.Fatalf("unexpected error reading secret: %v", err)
	}

	if info.Path != "secret/myapp/db" {
		t.Errorf("expected path %q, got %q", "secret/myapp/db", info.Path)
	}
	if info.LeaseTTL != 3600*time.Second {
		t.Errorf("expected lease TTL 3600s, got %v", info.LeaseTTL)
	}
	if !info.Renewable {
		t.Error("expected secret to be renewable")
	}
	if info.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}
