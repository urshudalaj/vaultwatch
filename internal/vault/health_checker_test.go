package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newHealthMockServer(t *testing.T, status int, body HealthStatus) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestCheckHealth_Healthy(t *testing.T) {
	body := HealthStatus{Initialized: true, Sealed: false, Version: "1.15.0", ClusterName: "vault-cluster"}
	srv := newHealthMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := NewHealthChecker(srv.URL, srv.Client())
	got, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Initialized {
		t.Error("expected Initialized=true")
	}
	if got.Version != "1.15.0" {
		t.Errorf("expected version 1.15.0, got %s", got.Version)
	}
}

func TestCheckHealth_Standby(t *testing.T) {
	body := HealthStatus{Initialized: true, Sealed: false, Standby: true, Version: "1.15.0"}
	srv := newHealthMockServer(t, 429, body)
	defer srv.Close()

	checker := NewHealthChecker(srv.URL, srv.Client())
	got, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on standby: %v", err)
	}
	if !got.Standby {
		t.Error("expected Standby=true")
	}
}

func TestCheckHealth_ErrorOnServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	checker := NewHealthChecker(srv.URL, srv.Client())
	_, err := checker.Check(context.Background())
	if err == nil {
		t.Fatal("expected error on 500 status")
	}
}
