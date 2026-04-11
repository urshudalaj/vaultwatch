package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newSealMockServer(t *testing.T, status vault.SealStatus, httpStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(httpStatus)
		_ = json.NewEncoder(w).Encode(status)
	}))
}

func TestCheckSeal_Unsealed(t *testing.T) {
	expected := vault.SealStatus{
		Sealed:      false,
		Initialized: true,
		ClusterName: "vault-cluster",
		Version:     "1.15.0",
	}
	srv := newSealMockServer(t, expected, http.StatusOK)
	defer srv.Close()

	checker := vault.NewSealChecker(srv.Client(), srv.URL)
	got, err := checker.CheckSeal(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Sealed != expected.Sealed {
		t.Errorf("Sealed: got %v, want %v", got.Sealed, expected.Sealed)
	}
	if got.ClusterName != expected.ClusterName {
		t.Errorf("ClusterName: got %q, want %q", got.ClusterName, expected.ClusterName)
	}
}

func TestCheckSeal_Sealed(t *testing.T) {
	expected := vault.SealStatus{Sealed: true, Initialized: true}
	srv := newSealMockServer(t, expected, http.StatusOK)
	defer srv.Close()

	checker := vault.NewSealChecker(srv.Client(), srv.URL)
	got, err := checker.CheckSeal(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Sealed {
		t.Error("expected Sealed=true")
	}
}

func TestCheckSeal_ErrorOnBadStatus(t *testing.T) {
	srv := newSealMockServer(t, vault.SealStatus{}, http.StatusInternalServerError)
	defer srv.Close()

	checker := vault.NewSealChecker(srv.Client(), srv.URL)
	_, err := checker.CheckSeal(context.Background())
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
