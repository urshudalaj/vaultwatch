package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newPolicyMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/policy/read-only":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":  "read-only",
				"rules": `path "secret/*" { capabilities = ["read"] }`,
			})
		case "/v1/sys/policy":
			w.Header().Set("X-Vault-Index", "1")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []string{"default", "read-only", "root"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func newPolicyAPIClient(t *testing.T, addr string) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	c, err := vaultapi.NewClient(cfg)
	require.NoError(t, err)
	c.SetToken("test-token")
	return c
}

func TestGetPolicy_ReturnsRules(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()

	client := newPolicyAPIClient(t, srv.URL)
	pc := vault.NewPolicyChecker(client)

	info, err := pc.GetPolicy(context.Background(), "read-only")
	require.NoError(t, err)
	assert.Equal(t, "read-only", info.Name)
	assert.Contains(t, info.Rules, "capabilities")
}

func TestGetPolicy_ErrorOnEmptyName(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()

	client := newPolicyAPIClient(t, srv.URL)
	pc := vault.NewPolicyChecker(client)

	_, err := pc.GetPolicy(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestListPolicies_ReturnsNames(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()

	client := newPolicyAPIClient(t, srv.URL)
	pc := vault.NewPolicyChecker(client)

	names, err := pc.ListPolicies(context.Background())
	require.NoError(t, err)
	assert.Len(t, names, 3)
	assert.Contains(t, names, "read-only")
}
