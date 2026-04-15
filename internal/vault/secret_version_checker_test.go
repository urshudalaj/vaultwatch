package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSecretVersionMockServer(t *testing.T, status int, payload any) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

func TestGetSecretVersionInfo_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"current_version": 3,
			"oldest_version":  1,
			"max_versions":    10,
			"versions": map[string]any{
				"1": map[string]any{},
				"2": map[string]any{},
				"3": map[string]any{},
			},
		},
	}
	srv, client := newSecretVersionMockServer(t, http.StatusOK, payload)
	checker := NewSecretVersionChecker(srv.URL, "tok", client)
	info, err := checker.GetSecretVersionInfo("secret", "myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CurrentVersion != 3 {
		t.Errorf("expected current_version 3, got %d", info.CurrentVersion)
	}
	if info.VersionCount != 3 {
		t.Errorf("expected 3 versions, got %d", info.VersionCount)
	}
	if info.MaxVersions != 10 {
		t.Errorf("expected max_versions 10, got %d", info.MaxVersions)
	}
}

func TestGetSecretVersionInfo_ErrorOnEmptyParams(t *testing.T) {
	checker := NewSecretVersionChecker("http://localhost", "tok", nil)
	_, err := checker.GetSecretVersionInfo("", "path")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = checker.GetSecretVersionInfo("mount", "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestGetSecretVersionInfo_ErrorOnBadStatus(t *testing.T) {
	srv, client := newSecretVersionMockServer(t, http.StatusForbidden, nil)
	checker := NewSecretVersionChecker(srv.URL, "bad-tok", client)
	_, err := checker.GetSecretVersionInfo("secret", "myapp/db")
	if err == nil {
		t.Fatal("expected error on 403 status")
	}
}
