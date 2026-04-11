package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAuditMockServer(t *testing.T, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestListAuditDevices_ReturnsDevices(t *testing.T) {
	payload := map[string]interface{}{
		"file/": map[string]string{"type": "file", "description": "file audit log"},
		"syslog/": map[string]string{"type": "syslog", "description": "syslog audit"},
	}
	srv := newAuditMockServer(t, payload, http.StatusOK)
	defer srv.Close()

	checker := NewAuditChecker(srv.URL, "test-token", nil)
	devices, err := checker.ListAuditDevices(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	for _, d := range devices {
		if !d.Enabled {
			t.Errorf("device %s should be enabled", d.Path)
		}
	}
}

func TestListAuditDevices_ErrorOnBadStatus(t *testing.T) {
	srv := newAuditMockServer(t, nil, http.StatusForbidden)
	defer srv.Close()

	checker := NewAuditChecker(srv.URL, "bad-token", nil)
	// Override token check: server returns 403 for missing token; use empty token
	checker.token = ""
	_, err := checker.ListAuditDevices(context.Background())
	if err == nil {
		t.Fatal("expected error for forbidden status")
	}
}

func TestListAuditDevices_EmptyResponse(t *testing.T) {
	payload := map[string]interface{}{}
	srv := newAuditMockServer(t, payload, http.StatusOK)
	defer srv.Close()

	checker := NewAuditChecker(srv.URL, "test-token", nil)
	devices, err := checker.ListAuditDevices(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devices))
	}
}
