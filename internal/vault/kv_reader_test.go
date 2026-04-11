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

	"github.com/your-org/vaultwatch/internal/vault"
)

func newKVMockServer(t *testing.T, kvVersion vault.KVVersion) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if kvVersion == vault.KVv2 {
			payload = map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{"username": "admin", "password": "s3cr3t"},
					"metadata": map[string]interface{}{"version": float64(3)},
				},
			}
		} else {
			payload = map[string]interface{}{
				"data": map[string]interface{}{"api_key": "abc123"},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}))
}

func newKVAPIClient(t *testing.T, serverURL string) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = serverURL
	c, err := vaultapi.NewClient(cfg)
	require.NoError(t, err)
	c.SetToken("test-token")
	return c
}

func TestReadSecret_KVv1(t *testing.T) {
	srv := newKVMockServer(t, vault.KVv1)
	defer srv.Close()

	client := newKVAPIClient(t, srv.URL)
	reader := vault.NewKVReader(client, "secret", vault.KVv1)

	secret, err := reader.ReadSecret(context.Background(), "myapp/config")
	require.NoError(t, err)
	assert.Equal(t, "myapp/config", secret.Path)
	assert.Equal(t, "abc123", secret.Data["api_key"])
	assert.Equal(t, 0, secret.Version)
}

func TestReadSecret_KVv2(t *testing.T) {
	srv := newKVMockServer(t, vault.KVv2)
	defer srv.Close()

	client := newKVAPIClient(t, srv.URL)
	reader := vault.NewKVReader(client, "secret", vault.KVv2)

	secret, err := reader.ReadSecret(context.Background(), "myapp/config")
	require.NoError(t, err)
	assert.Equal(t, "myapp/config", secret.Path)
	assert.Equal(t, "admin", secret.Data["username"])
	assert.Equal(t, 3, secret.Version)
}

func TestReadSecret_EmptyPath(t *testing.T) {
	srv := newKVMockServer(t, vault.KVv1)
	defer srv.Close()

	client := newKVAPIClient(t, srv.URL)
	reader := vault.NewKVReader(client, "secret", vault.KVv1)

	_, err := reader.ReadSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}
