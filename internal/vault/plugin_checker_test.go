package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPluginMockServer(t *testing.T, pluginType string, plugins []PluginInfo, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/sys/plugins/catalog/" + pluginType
		if r.URL.Path != expected {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"detailed": plugins,
				},
			})
		}
	}))
}

func newPluginAPIClient(t *testing.T, srv *httptest.Server) *PluginChecker {
	t.Helper()
	return NewPluginChecker(srv.Client(), srv.URL, "test-token")
}

func TestListPlugins_ReturnsPlugins(t *testing.T) {
	plugins := []PluginInfo{
		{Name: "aws", Type: "secret", Version: "v1.2.3", Builtin: true},
		{Name: "custom-auth", Type: "auth", Version: "v0.1.0", Builtin: false},
	}
	srv := newPluginMockServer(t, "secret", plugins, http.StatusOK)
	defer srv.Close()

	checker := newPluginAPIClient(t, srv)
	result, err := checker.ListPlugins("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(result))
	}
	if result[0].Name != "aws" {
		t.Errorf("expected first plugin name 'aws', got %q", result[0].Name)
	}
}

func TestListPlugins_ErrorOnEmptyType(t *testing.T) {
	checker := NewPluginChecker(http.DefaultClient, "http://localhost", "tok")
	_, err := checker.ListPlugins("")
	if err == nil {
		t.Fatal("expected error for empty plugin type")
	}
}

func TestListPlugins_ErrorOnBadStatus(t *testing.T) {
	srv := newPluginMockServer(t, "auth", nil, http.StatusForbidden)
	defer srv.Close()

	checker := newPluginAPIClient(t, srv)
	_, err := checker.ListPlugins("auth")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
