package monitor

import (
	"context"
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// GitHubConfigGetter retrieves GitHub auth configuration.
type GitHubConfigGetter interface {
	GetConfig(mount string) (*vault.GitHubRole, error)
}

// GitHubJob checks GitHub auth role TTL configuration.
type GitHubJob struct {
	checker GitHubConfigGetter
	mount   string
	send    AlertSender
}

// NewGitHubJob creates a new GitHubJob.
func NewGitHubJob(checker GitHubConfigGetter, mount string, send AlertSender) *GitHubJob {
	return &GitHubJob{checker: checker, mount: mount, send: send}
}

// Run checks the GitHub auth config and emits alerts for missing TTL fields.
func (j *GitHubJob) Run(ctx context.Context) {
	role, err := j.checker.GetConfig(j.mount)
	if err != nil {
		log.Printf("github_job: failed to get config for mount %q: %v", j.mount, err)
		return
	}
	if role.TTL == "" || role.TTL == "0" {
		j.send(Alert{
			Level:   Warning,
			Message: fmt.Sprintf("GitHub mount %q has no TTL configured", j.mount),
		})
	}
	if role.MaxTTL == "" || role.MaxTTL == "0" {
		j.send(Alert{
			Level:   Warning,
			Message: fmt.Sprintf("GitHub mount %q has no MaxTTL configured", j.mount),
		})
	}
	if role.Organization == "" {
		j.send(Alert{
			Level:   Critical,
			Message: fmt.Sprintf("GitHub mount %q has no organization configured", j.mount),
		})
	}
}
