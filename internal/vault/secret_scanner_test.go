package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
)

func newScannerMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "LIST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"db", "api"},
				},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"lease_id":       "secret/db/lease-abc",
			"lease_duration": 3600,
			"renewable":      true,
			"data":           map[string]string{"password": "s3cr3t"},
		})
	})
	return httptest.NewServer(mux)
}

func newTestAPIClient(t *testing.T, serverURL string) *api.Client {
	t.Helper()
	cfg := api.DefaultConfig()
	cfg.Address = serverURL
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create api client: %v", err)
	}
	client.SetToken("test-token")
	return client
}

func TestScanPath_ReturnsPaths(t *testing.T) {
	srv := newScannerMockServer(t)
	defer srv.Close()

	scanner := NewSecretScanner(newTestAPIClient(t, srv.URL))
	paths, err := scanner.ScanPath(context.Background(), "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(paths))
	}
}

func TestReadLeaseInfo_ReturnsLease(t *testing.T) {
	srv := newScannerMockServer(t)
	defer srv.Close()

	scanner := NewSecretScanner(newTestAPIClient(t, srv.URL))
	leaseID, duration, renewable, err := scanner.ReadLeaseInfo(context.Background(), "secret/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaseID != "secret/db/lease-abc" {
		t.Errorf("expected lease ID 'secret/db/lease-abc', got %q", leaseID)
	}
	if duration != 3600 {
		t.Errorf("expected duration 3600, got %d", duration)
	}
	if !renewable {
		t.Error("expected renewable to be true")
	}
}
