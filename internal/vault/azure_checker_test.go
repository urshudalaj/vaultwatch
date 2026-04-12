package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAzureMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newAzureAPIClient(baseURL, token string) *AzureChecker {
	return NewAzureChecker(http.DefaultClient, baseURL, token)
}

func TestGetAzureRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"application_object_id": "obj-123",
			"ttl":     "1h",
			"max_ttl": "24h",
		},
	}
	srv := newAzureMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := newAzureAPIClient(srv.URL, "test-token")
	info, err := c.GetAzureRole("azure", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ApplicationObjectID != "obj-123" {
		t.Errorf("expected obj-123, got %s", info.ApplicationObjectID)
	}
	if info.TTL != "1h" {
		t.Errorf("expected 1h TTL, got %s", info.TTL)
	}
}

func TestGetAzureRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	c := newAzureAPIClient("http://localhost", "tok")
	_, err := c.GetAzureRole("", "role")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = c.GetAzureRole("azure", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestGetAzureRole_ErrorOnBadStatus(t *testing.T) {
	srv := newAzureMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newAzureAPIClient(srv.URL, "bad-token")
	_, err := c.GetAzureRole("azure", "my-role")
	if err == nil {
		t.Fatal("expected error on 403")
	}
}
