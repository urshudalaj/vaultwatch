package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// NamespaceQuotaTarget identifies a quota to monitor within a namespace.
type NamespaceQuotaTarget struct {
	Namespace string
	Name      string
	MinRate   float64 // alert if rate drops below this threshold
}

// NamespaceQuotaChecker is the interface satisfied by vault.NamespaceQuotaChecker.
type NamespaceQuotaChecker interface {
	GetNamespaceQuota(namespace, name string) (*vault.NamespaceQuotaInfo, error)
}

// NamespaceQuotaJob monitors rate-limit quotas scoped to Vault namespaces.
type NamespaceQuotaJob struct {
	checker NamespaceQuotaChecker
	targets []NamespaceQuotaTarget
}

// NewNamespaceQuotaJob constructs a NamespaceQuotaJob.
func NewNamespaceQuotaJob(checker NamespaceQuotaChecker, targets []NamespaceQuotaTarget) *NamespaceQuotaJob {
	return &NamespaceQuotaJob{checker: checker, targets: targets}
}

// Run checks each namespace quota target and returns alerts for any issues found.
func (j *NamespaceQuotaJob) Run(_ context.Context) ([]Alert, error) {
	var alerts []Alert
	for _, t := range j.targets {
		info, err := j.checker.GetNamespaceQuota(t.Namespace, t.Name)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("namespace quota check failed for %s/%s: %v", t.Namespace, t.Name, err),
			})
			continue
		}
		if info.Rate < t.MinRate {
			alerts = append(alerts, Alert{
				Level: LevelCritical,
				Message: fmt.Sprintf(
					"namespace quota %s/%s rate %.2f is below minimum %.2f",
					t.Namespace, t.Name, info.Rate, t.MinRate,
				),
			})
		}
	}
	return alerts, nil
}
