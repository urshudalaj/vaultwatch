package monitor

import (
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// SSHRoleGetter retrieves SSH role info from Vault.
type SSHRoleGetter interface {
	GetRole(mount, role string) (*vault.SSHRoleInfo, error)
}

// SSHJobConfig holds the configuration for the SSH role monitor job.
type SSHJobConfig struct {
	Mounts []string // e.g. ["ssh", "ssh-prod"]
	Roles  []string // roles to check within each mount
}

// SSHJob monitors SSH secret engine roles for missing or misconfigured TTLs.
type SSHJob struct {
	checker SSHRoleGetter
	cfg     SSHJobConfig
	alerts  func(Alert)
}

// NewSSHJob creates a new SSHJob.
func NewSSHJob(checker SSHRoleGetter, cfg SSHJobConfig, onAlert func(Alert)) *SSHJob {
	return &SSHJob{checker: checker, cfg: cfg, alerts: onAlert}
}

// Run checks each configured mount/role pair and emits alerts for any
// roles with an empty TTL or MaxTTL (indicating unconstrained certificate lifetimes).
func (j *SSHJob) Run() {
	for _, mount := range j.cfg.Mounts {
		for _, role := range j.cfg.Roles {
			info, err := j.checker.GetRole(mount, role)
			if err != nil {
				log.Printf("ssh_job: skipping %s/%s: %v", mount, role, err)
				continue
			}
			if info.TTL == "" || info.TTL == "0" {
				j.alerts(Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("SSH role %s/%s has no TTL configured", mount, role),
				})
			}
			if info.MaxTTL == "" || info.MaxTTL == "0" {
				j.alerts(Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("SSH role %s/%s has no MaxTTL configured", mount, role),
				})
			}
		}
	}
}
