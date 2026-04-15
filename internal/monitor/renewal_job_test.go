package monitor_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourusername/vaultwatch/internal/monitor"
	"github.com/yourusername/vaultwatch/internal/vault"
)

// stubRenewalChecker implements a test double for the renewal checker.
type stubRenewalChecker struct {
	info *vault.RenewalInfo
	err  error
}

func (s *stubRenewalChecker) CheckRenewal(leaseID string) (*vault.RenewalInfo, error) {
	return s.info,nfunc renewalJobWithStub(checker *stubRenewalChecker, warnThreshold time.Duration) *monitor.RenewalJob {
	return monitor.NewRenewalJob(checker, leaseID, warnThreshold)
}

func TestRenewalJob_NoAlertWhenHealthy(t *testing.T) {
	checker := &stubRenewalChecker{
		info: &vault.RenewalInfo{
			LeaseID:       "lease/abc123",
			TTL:           3600,
			Renewable:     true,
			ExpireTime:    time.Now().Add(2 * time.Hour),
		},
	}
	job := renewalJobWithStub(checker, "lease/abc123", 30*time.Minute)

	alerts, err := job.Run()
	require.NoError(t, err)
	assert.Empty(t, alerts)
}

func TestRenewalJob_AlertWhenExpiringSoon(t *testing.T) {
	checker := &stubRenewalChecker{
		info: &vault.RenewalInfo{
			LeaseID:    "lease/abc123",
			TTL:        600,
			Renewable:  true,
			ExpireTime: time.Now().Add(10 * time.Minute),
		},
	}
	job := renewalJobWithStub(checker, "lease/abc123", 30*time.Minute)

	alerts, err := job.Run()
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Contains(t, alerts[0].Message, "lease/abc123")
	assert.Equal(t, monitor.SeverityWarning, alerts[0].Severity)
}

func TestRenewalJob_AlertWhenExpired(t *testing.T) {
	checker := &stubRenewalChecker{
		info: &vault.RenewalInfo{
			LeaseID:    "lease/abc123",
			TTL:        0,
			Renewable:  false,
			ExpireTime: time.Now().Add(-5 * time.Minute),
		},
	}
	job := renewalJobWithStub(checker, "lease/abc123", 30*time.Minute)

	alerts, err := job.Run()
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, monitor.SeverityCritical, alerts[0].Severity)
	assert.Contains(t, alerts[0].Message, "expired")
}

func TestRenewalJob_AlertWhenNotRenewable(t *testing.T) {
	checker := &stubRenewalChecker{
		info: &vault.RenewalInfo{
			LeaseID:    "lease/abc123",
			TTL:        300,
			Renewable:  false,
			ExpireTime: time.Now().Add(5 * time.Minute),
		},
	}
	job := renewalJobWithStub(checker, "lease/abc123", 30*time.Minute)

	alerts, err := job.Run()
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Contains(t, alerts[0].Message, "not renewable")
}

func TestRenewalJob_SkipsAlertOnCheckerError(t *testing.T) {
	checker := &stubRenewalChecker{
		err: errors.New("vault unreachable"),
	}
	job := renewalJobWithStub(checker, "lease/abc123", 30*time.Minute)

	alerts, err := job.Run()
	require.Error(t, err)
	assert.Empty(t, alerts)
}
