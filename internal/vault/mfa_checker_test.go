package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newMFAMockServer(t *testing.T, status int, methods []MFAMethod) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		payload := map[string]interface{}{
			"data": map[string]interface{}{
				"key_info": methods,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}))
}

func newMFAAPIClient(srv *httptest.Server) *MFAChecker {
	return NewMFAChecker(srv.Client(), srv.URL, "test-token")
}

func TestListMFAMethods_ReturnsMethods(t *testing.T) {
	methods := []MFAMethod{
		{ID: "abc-123", Name: "duo", Type: "duo"},
		{ID: "def-456", Name: "totp", Type: "totp"},
	}
	srv := newMFAMockServer(t, http.StatusOK, methods)
	defer srv.Close()

	checker := newMFAAPIClient(srv)
	got, err := checker.ListMFAMethods()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(got))
	}
	if got[0].Type != "duo" {
		t.Errorf("expected type duo, got %s", got[0].Type)
	}
}

func TestListMFAMethods_ErrorOnBadStatus(t *testing.T) {
	srv := newMFAMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newMFAAPIClient(srv)
	_, err := checker.ListMFAMethods()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListMFAMethods_EmptyResponse(t *testing.T) {
	srv := newMFAMockServer(t, http.StatusOK, []MFAMethod{})
	defer srv.Close()

	checker := newMFAAPIClient(srv)
	got, err := checker.ListMFAMethods()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d items", len(got))
	}
}
