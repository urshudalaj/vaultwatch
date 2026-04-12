package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newCAMockServer(t *testing.T, mount string, expiration int64, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/" + mount + "/cert/ca"
		if r.URL.Path != expected {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"expiration": expiration,
					"issuing_ca": "CN=VaultCA",
				},
			})
		}
	}))
}

func TestCheckCA_ReturnsInfo(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).Unix()
	srv := newCAMockServer(t, "pki", expiry, http.StatusOK)
	defer srv.Close()

	checker := NewCAChecker(srv.URL, "test-token", nil)
	info, err := checker.CheckCA("pki")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Mount != "pki" {
		t.Errorf("expected mount pki, got %s", info.Mount)
	}
	if info.Issuer != "CN=VaultCA" {
		t.Errorf("expected issuer CN=VaultCA, got %s", info.Issuer)
	}
	if info.Expiration.Unix() != expiry {
		t.Errorf("expected expiration %d, got %d", expiry, info.Expiration.Unix())
	}
}

func TestCheckCA_ErrorOnEmptyMount(t *testing.T) {
	checker := NewCAChecker("http://localhost", "token", nil)
	_, err := checker.CheckCA("")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
}

func TestCheckCA_ErrorOnBadStatus(t *testing.T) {
	srv := newCAMockServer(t, "pki", 0, http.StatusForbidden)
	defer srv.Close()

	checker := NewCAChecker(srv.URL, "bad-token", nil)
	_, err := checker.CheckCA("pki")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
