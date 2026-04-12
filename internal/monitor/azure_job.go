package monitor

import (
	"context"
	"fmt"

	"github.com/subtlepseudonym/vaultwatch/internal/vault"
)

// AzureRoleGetter retrieves Azure secrets engine role info.
type AzureRoleGetter interface {
	GetAzureRole(mount, role string) (*vault.AzureRoleInfo, error)
}

// AzureJobConfig holds configuration for the Azure monitor job.
type AzureJobConfig struct {
	Mount string
	Role  string
}

// NewAzureJob returns a RunFunc that checks an Azure secrets role for missing TTL configuration.
func NewAzureJob(checker AzureRoleGetter, cfg AzureJobConfig, send AlertSender) RunFunc {
	return func(ctx context.Context) error {
		info, err := checker.GetAzureRole(cfg.Mount, cfg.Role)
		if err != nil {
			return fmt.Errorf("azure_job: get role: %w", err)
		}

		path := fmt.Sprintf("%s/roles/%s", cfg.Mount, cfg.Role)

		if info.TTL == "" || info.TTL == "0" {
			send(Alert{
				Level:   Warning,
				Message: fmt.Sprintf("Azure role %s has no TTL configured", path),
				Path:    path,
			})
		}

		if info.MaxTTL == "" || info.MaxTTL == "0" {
			send(Alert{
				Level:   Warning,
				Message: fmt.Sprintf("Azure role %s has no max_ttl configured", path),
				Path:    path,
			})
		}

		return nil
	}
}
