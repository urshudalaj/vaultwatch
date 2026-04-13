package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubMFALister struct {
	methods []vault.MFAMethod
	err     error
}

func (s *stubMFALister) ListMFAMethods() ([]vault.MFAMethod, error) {
	return s.methods, s.err
}

func mfaJobWithStub(methods []vault.MFAMethod, err error) *MFAJob {
	return NewMFAJob(&stubMFALister{methods: methods, err: err})
}

func TestMFAJob_NoAlertWhenMethodsPresent(t *testing.T) {
	job := mfaJobWithStub([]vault.MFAMethod{
		{ID: "1", Name: "duo", Type: "duo"},
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestMFAJob_AlertWhenNoMethods(t *testing.T) {
	job := mfaJobWithStub([]vault.MFAMethod{}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %s", alerts[0].Level)
	}
}

func TestMFAJob_AlertWhenMethodMissingType(t *testing.T) {
	job := mfaJobWithStub([]vault.MFAMethod{
		{ID: "2", Name: "unknown", Type: ""},
	}, nil)
	alerts, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %s", alerts[0].Level)
	}
}

func TestMFAJob_SkipsAlertOnListerError(t *testing.T) {
	job := mfaJobWithStub(nil, errors.New("vault unavailable"))
	_, err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
