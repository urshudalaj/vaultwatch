package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSentinelMockServer(t *testing.T, kind string, keys []string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		body := map[string]interface{}{
			"data": map[string]interface{}{"keys": keys},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
}

func newSentinelAPIClient(baseURL string) *SentinelChecker {
	return NewSentinelChecker(http.DefaultClient, baseURL, "test-token")
}

func TestListEGPs_ReturnsPolicies(t *testing.T) {
	expected := []string{"egp-allow-prod", "egp-deny-dev"}
	srv := newSentinelMockServer(t, "egp", expected, http.StatusOK)
	defer srv.Close()

	checker := newSentinelAPIClient(srv.URL)
	got, err := checker.ListEGPs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(got))
	}
	for i, name := range expected {
		if got[i] != name {
			t.Errorf("policy[%d]: want %q, got %q", i, name, got[i])
		}
	}
}

func TestListRGPs_ReturnsPolicies(t *testing.T) {
	expected := []string{"rgp-global"}
	srv := newSentinelMockServer(t, "rgp", expected, http.StatusOK)
	defer srv.Close()

	checker := newSentinelAPIClient(srv.URL)
	got, err := checker.ListRGPs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "rgp-global" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestListEGPs_ErrorOnBadStatus(t *testing.T) {
	srv := newSentinelMockServer(t, "egp", nil, http.StatusForbidden)
	defer srv.Close()

	checker := newSentinelAPIClient(srv.URL)
	_, err := checker.ListEGPs(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
