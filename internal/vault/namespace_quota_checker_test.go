package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newNamespaceQuotaMockServer(t *testing.T, namespace, name string, info NamespaceQuotaInfo, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/" + namespace + "/sys/quotas/rate-limit/" + name
		if r.URL.Path != expected {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": info})
		}
	}))
}

func TestGetNamespaceQuota_ReturnsInfo(t *testing.T) {
	expected := NamespaceQuotaInfo{
		Name:      "my-quota",
		Namespace: "team-a",
		Type:      "rate-limit",
		Rate:      100,
		Interval:  1,
	}
	srv := newNamespaceQuotaMockServer(t, "team-a", "my-quota", expected, http.StatusOK)
	defer srv.Close()

	checker := NewNamespaceQuotaChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetNamespaceQuota("team-a", "my-quota")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != expected.Name {
		t.Errorf("expected name %q, got %q", expected.Name, info.Name)
	}
	if info.Rate != expected.Rate {
		t.Errorf("expected rate %v, got %v", expected.Rate, info.Rate)
	}
}

func TestGetNamespaceQuota_ErrorOnEmptyParams(t *testing.T) {
	checker := NewNamespaceQuotaChecker("http://localhost", "token", nil)
	_, err := checker.GetNamespaceQuota("", "my-quota")
	if err == nil {
		t.Fatal("expected error for empty namespace")
	}
	_, err = checker.GetNamespaceQuota("team-a", "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestGetNamespaceQuota_ErrorOnBadStatus(t *testing.T) {
	srv := newNamespaceQuotaMockServer(t, "team-a", "missing", NamespaceQuotaInfo{}, http.StatusNotFound)
	defer srv.Close()

	checker := NewNamespaceQuotaChecker(srv.URL, "test-token", srv.Client())
	_, err := checker.GetNamespaceQuota("team-a", "missing")
	if err == nil {
		t.Fatal("expected error on 404 response")
	}
}
