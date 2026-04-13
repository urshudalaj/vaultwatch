package monitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubGitHubChecker struct {
	role *vault.GitHubRole
	err  error
}

func (s *stubGitHubChecker) GetConfig(_ string) (*vault.GitHubRole, error) {
	return s.role, s.err
}

func githubJobWithStub(role *vault.GitHubRole, err error) (*GitHubJob, *[]Alert) {
	var alerts []Alert
	send := func(a Alert) { alerts = append(alerts, a) }
	checker := &stubGitHubChecker{role: role, err: err}
	return NewGitHubJob(checker, "github", send), &alerts
}

func TestGitHubJob_NoAlertWhenConfigured(t *testing.T) {
	role := &vault.GitHubRole{Organization: "acme", TTL: "1h", MaxTTL: "24h"}
	job, alerts := githubJobWithStub(role, nil)
	job.Run(context.Background())
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(*alerts))
	}
}

func TestGitHubJob_AlertWhenTTLMissing(t *testing.T) {
	role := &vault.GitHubRole{Organization: "acme", TTL: "", MaxTTL: "24h"}
	job, alerts := githubJobWithStub(role, nil)
	job.Run(context.Background())
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Warning {
		t.Errorf("expected Warning, got %v", (*alerts)[0].Level)
	}
}

func TestGitHubJob_AlertWhenMaxTTLMissing(t *testing.T) {
	role := &vault.GitHubRole{Organization: "acme", TTL: "1h", MaxTTL: ""}
	job, alerts := githubJobWithStub(role, nil)
	job.Run(context.Background())
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Warning {
		t.Errorf("expected Warning, got %v", (*alerts)[0].Level)
	}
}

func TestGitHubJob_AlertWhenOrgMissing(t *testing.T) {
	role := &vault.GitHubRole{Organization: "", TTL: "1h", MaxTTL: "24h"}
	job, alerts := githubJobWithStub(role, nil)
	job.Run(context.Background())
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Critical {
		t.Errorf("expected Critical, got %v", (*alerts)[0].Level)
	}
}

func TestGitHubJob_SkipsAlertOnCheckerError(t *testing.T) {
	job, alerts := githubJobWithStub(nil, fmt.Errorf("connection refused"))
	job.Run(context.Background())
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts on error, got %d", len(*alerts))
	}
}
