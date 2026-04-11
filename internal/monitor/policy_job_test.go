package monitor_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourusername/vaultwatch/internal/monitor"
	"github.com/yourusername/vaultwatch/internal/vault"
)

// stubPolicyWatcher implements monitor.PolicyWatcher for tests.
type stubPolicyWatcher struct {
	policies map[string]string // name -> rules
}

func (s *stubPolicyWatcher) ListPolicies(_ context.Context) ([]string, error) {
	names := make([]string, 0, len(s.policies))
	for n := range s.policies {
		names = append(names, n)
	}
	return names, nil
}

func (s *stubPolicyWatcher) GetPolicy(_ context.Context, name string) (*vault.PolicyInfo, error) {
	rules, ok := s.policies[name]
	if !ok {
		return nil, nil
	}
	return &vault.PolicyInfo{Name: name, Rules: rules}, nil
}

// captureAlerter records sent alerts.
type captureAlerter struct {
	alerts []monitor.Alert
}

func (c *captureAlerter) Send(a monitor.Alert) { c.alerts = append(c.alerts, a) }

func TestPolicyJob_NoAlertWhenClean(t *testing.T) {
	w := &stubPolicyWatcher{
		policies: map[string]string{
			"safe": `path "secret/data/*" { capabilities = ["read"] }`,
		},
	}
	a := &captureAlerter{}
	job := monitor.NewPolicyJob(w, a, []string{"sudo", "*"})

	err := job.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, a.alerts)
}

func TestPolicyJob_AlertOnBannedFragment(t *testing.T) {
	w := &stubPolicyWatcher{
		policies: map[string]string{
			"dangerous": `path "*" { capabilities = ["sudo"] }`,
		},
	}
	a := &captureAlerter{}
	job := monitor.NewPolicyJob(w, a, []string{"sudo"})

	err := job.Run(context.Background())
	require.NoError(t, err)
	require.Len(t, a.alerts, 1)
	assert.Equal(t, monitor.AlertWarning, a.alerts[0].Level)
	assert.Contains(t, a.alerts[0].Message, "dangerous")
	assert.Contains(t, a.alerts[0].Message, "sudo")
}

func TestPolicyJob_AlertOncePerPolicy(t *testing.T) {
	w := &stubPolicyWatcher{
		policies: map[string]string{
			"broad": `path "*" { capabilities = ["sudo", "create"] }`,
		},
	}
	a := &captureAlerter{}
	job := monitor.NewPolicyJob(w, a, []string{"sudo", "*"})

	err := job.Run(context.Background())
	require.NoError(t, err)
	// Should only fire once per policy even if multiple fragments match.
	assert.Len(t, a.alerts, 1)
}
