package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAWSMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newAWSAPIClient(t *testing.T, addr string) *AWSChecker {
	t.Helper()
	return &AWSChecker{
		client: &http.Client{},
		base:   addr,
		token:  "test-token",
	}
}

func TestGetAWSRole_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"credential_type": "iam_user",
			"default_ttl":     3600,
			"max_ttl":         86400,
		},
	}
	srv := newAWSMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newAWSAPIClient(t, srv.URL)
	info, err := checker.GetRole("aws", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CredentialType != "iam_user" {
		t.Errorf("expected credential_type iam_user, got %s", info.CredentialType)
	}
	if info.DefaultTTL != 3600 {
		t.Errorf("expected default_ttl 3600, got %d", info.DefaultTTL)
	}
	if info.Mount != "aws" || info.Role != "my-role" {
		t.Errorf("expected mount/role set, got %s/%s", info.Mount, info.Role)
	}
}

func TestGetAWSRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := &AWSChecker{client: &http.Client{}, base: "http://localhost", token: "t"}

	if _, err := checker.GetRole("", "role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetRole("aws", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetAWSRole_ErrorOnBadStatus(t *testing.T) {
	srv := newAWSMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newAWSAPIClient(t, srv.URL)
	if _, err := checker.GetRole("aws", "role"); err == nil {
		t.Error("expected error on non-200 status")
	}
}
