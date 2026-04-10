package monitor

import (
	"context"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/yourusername/vaultwatch/internal/vault"
)

func newTokenWatcher(t *testing.T, ttl time.Duration, renewable bool) *vault.TokenWatcher {
	t.Helper()
	// Build a minimal fake client; LookupSelf will fail but we stub via interface
	cfg := vaultapi.DefaultConfig()
	cfg.Address = "http://127.0.0.1:1" // unreachable, tests use stubWatcher below
	client, _ := vaultapi.NewClient(cfg)
	_ = client
	return nil // replaced by stubWatcher in tests
}

type stubTokenWatcher struct {
	info      *vault.TokenInfo
	renewErr  error
	renewCalled bool
}

func (s *stubTokenWatcher) LookupSelf(_ context.Context) (*vault.TokenInfo, error) {
	return s.info, nil
}

func (s *stubTokenWatcher) RenewSelf(_ context.Context, _ int) error {
	s.renewCalled = true
	return s.renewErr
}

// tokenJobWithStub wires a stubTokenWatcher directly for testing.
func tokenJobWithStub(stub *stubTokenWatcher, cfg TokenJobConfig, ch chan<- Alert) *TokenJob {
	return &TokenJob{watcher: nil, cfg: cfg, alerts: ch}
}

func TestTokenJob_NoAlertWhenHealthy(t *testing.T) {
	ch := make(chan Alert, 5)
	cfg := TokenJobConfig{
		WarnThreshold:     30 * time.Minute,
		CriticalThreshold: 5 * time.Minute,
	}
	alerts, watcher := runTokenJobStub(t, 2*time.Hour, true, cfg, ch)
	_ = watcher
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestTokenJob_WarningAlert(t *testing.T) {
	ch := make(chan Alert, 5)
	cfg := TokenJobConfig{
		WarnThreshold:     30 * time.Minute,
		CriticalThreshold: 5 * time.Minute,
	}
	alerts, _ := runTokenJobStub(t, 20*time.Minute, true, cfg, ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Warning {
		t.Errorf("expected Warning, got %v", alerts[0].Level)
	}
}

func TestTokenJob_CriticalAlert(t *testing.T) {
	ch := make(chan Alert, 5)
	cfg := TokenJobConfig{
		WarnThreshold:     30 * time.Minute,
		CriticalThreshold: 5 * time.Minute,
	}
	alerts, _ := runTokenJobStub(t, 2*time.Minute, false, cfg, ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Level != Critical {
		t.Errorf("expected Critical, got %v", alerts[0].Level)
	}
}

func runTokenJobStub(t *testing.T, ttl time.Duration, renewable bool, cfg TokenJobConfig, ch chan Alert) ([]Alert, *stubTokenWatcher) {
	t.Helper()
	stub := &stubTokenWatcher{
		info: &vault.TokenInfo{
			Accessor:  "acc-123",
			TTL:       ttl,
			Renewable: renewable,
			Policies:  []string{"default"},
		},
	}
	job := &TokenJob{watcher: nil, cfg: cfg, alerts: ch}
	// Directly invoke logic via a helper that accepts the stub
	runTokenJobLogic(job, stub, context.Background())
	close(ch)
	var alerts []Alert
	for a := range ch {
		alerts = append(alerts, a)
	}
	return alerts, stub
}
