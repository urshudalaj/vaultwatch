package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSecretCountMockServer(t *testing.T, keys []string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		body := map[string]interface{}{
			"data": map[string]interface{}{
				"keys": keys,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
}

func TestCountSecrets_ReturnsInfo(t *testing.T) {
	keys := []string{"secret1", "secret2", "folder/"}
	srv := newSecretCountMockServer(t, keys, http.StatusOK)
	defer srv.Close()

	checker := NewSecretCountChecker(srv.URL, "test-token", nil)
	info, err := checker.CountSecrets("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TotalKeys != 2 {
		t.Errorf("expected 2 keys, got %d", info.TotalKeys)
	}
	if info.Subfolders != 1 {
		t.Errorf("expected 1 subfolder, got %d", info.Subfolders)
	}
	if info.Mount != "secret" {
		t.Errorf("expected mount 'secret', got %q", info.Mount)
	}
}

func TestCountSecrets_ErrorOnEmptyMount(t *testing.T) {
	checker := NewSecretCountChecker("http://localhost", "token", nil)
	_, err := checker.CountSecrets("")
	if err == nil {
		t.Fatal("expected error for empty mount, got nil")
	}
}

func TestCountSecrets_ErrorOnBadStatus(t *testing.T) {
	srv := newSecretCountMockServer(t, nil, http.StatusForbidden)
	defer srv.Close()

	checker := NewSecretCountChecker(srv.URL, "bad-token", nil)
	_, err := checker.CountSecrets("secret")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}
