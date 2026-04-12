package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newKubernetesMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/role/" + role
		if r.URL.Path != expected {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newKubernetesAPIClient(t *testing.T, addr string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(addr, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestGetKubernetesRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"bound_service_account_names":      []string{"default"},
			"bound_service_account_namespaces": []string{"kube-system"},
			"ttl":           "1h",
			"max_ttl":        "24h",
			"token_policies": []string{"read-only"},
		},
	}
	srv := newKubernetesMockServer(t, "kubernetes", "my-role", payload, http.StatusOK)
	defer srv.Close()

	client := newKubernetesAPIClient(t, srv.URL)
	checker := vault.NewKubernetesChecker(client)

	role, err := checker.GetRole("kubernetes", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL != "1h" {
		t.Errorf("expected TTL '1h', got %q", role.TTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected MaxTTL '24h', got %q", role.MaxTTL)
	}
	if len(role.BoundServiceAccountNames) != 1 || role.BoundServiceAccountNames[0] != "default" {
		t.Errorf("unexpected BoundServiceAccountNames: %v", role.BoundServiceAccountNames)
	}
}

func TestGetKubernetesRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	client := newKubernetesAPIClient(t, "http://localhost")
	checker := vault.NewKubernetesChecker(client)

	if _, err := checker.GetRole("", "my-role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetRole("kubernetes", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetKubernetesRole_ErrorOnBadStatus(t *testing.T) {
	srv := newKubernetesMockServer(t, "kubernetes", "bad-role", nil, http.StatusForbidden)
	defer srv.Close()

	client := newKubernetesAPIClient(t, srv.URL)
	checker := vault.NewKubernetesChecker(client)

	if _, err := checker.GetRole("kubernetes", "bad-role"); err == nil {
		t.Error("expected error on 403 response")
	}
}
