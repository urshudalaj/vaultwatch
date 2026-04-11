package monitor

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/your-org/vaultwatch/internal/vault"
)

// KVChecker is implemented by vault.KVReader.
type KVChecker interface {
	ReadSecret(ctx context.Context, secretPath string) (*vault.KVSecret, error)
}

// KVJobConfig holds configuration for a KV secret check job.
type KVJobConfig struct {
	Paths           []string
	BannedKeywords  []string
	AlertSeverity   string
}

// KVJob scans KV secrets for banned keywords and emits alerts.
type KVJob struct {
	reader  KVChecker
	cfg     KVJobConfig
	alerts  chan Alert
}

// NewKVJob creates a KVJob that reads the given paths and checks for banned keywords.
func NewKVJob(reader KVChecker, cfg KVJobConfig, alerts chan Alert) *KVJob {
	return &KVJob{reader: reader, cfg: cfg, alerts: alerts}
}

// Run executes the KV scan job, reading each path and inspecting secret values.
func (j *KVJob) Run(ctx context.Context) error {
	for _, p := range j.cfg.Paths {
		secret, err := j.reader.ReadSecret(ctx, p)
		if err != nil {
			log.Printf("kv_job: skipping %s: %v", p, err)
			continue
		}

		for key, val := range secret.Data {
			strVal := fmt.Sprintf("%v", val)
			for _, kw := range j.cfg.BannedKeywords {
				if strings.Contains(strings.ToLower(strVal), strings.ToLower(kw)) {
					j.alerts <- Alert{
						Severity: j.cfg.AlertSeverity,
						Message: fmt.Sprintf("KV secret %s field '%s' contains banned keyword '%s'", p, key, kw),
						Path:     p,
					}
				}
			}
		}
	}
	return nil
}
