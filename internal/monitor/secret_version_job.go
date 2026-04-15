package monitor

import (
	"context"
	"fmt"
)

// SecretVersionTarget describes a KV v2 secret to inspect.
type SecretVersionTarget struct {
	Mount          string
	Path           string
	MaxVersions    int // alert if max_versions below this threshold
	MinVersionDrift int // alert if (current - oldest) exceeds this
}

// SecretVersionInfoer is the interface for fetching secret version metadata.
type SecretVersionInfoer interface {
	GetSecretVersionInfo(mount, path string) (*SecretVersionInfo, error)
}

// SecretVersionJob checks KV v2 secrets for version hygiene issues.
type SecretVersionJob struct {
	checker SecretVersionInfoer
	targets []SecretVersionTarget
}

// NewSecretVersionJob creates a SecretVersionJob.
func NewSecretVersionJob(checker SecretVersionInfoer, targets []SecretVersionTarget) *SecretVersionJob {
	return &SecretVersionJob{checker: checker, targets: targets}
}

// Run inspects each target and returns alerts for any hygiene issues found.
func (j *SecretVersionJob) Run(_ context.Context) ([]Alert, error) {
	var alerts []Alert
	for _, t := range j.targets {
		info, err := j.checker.GetSecretVersionInfo(t.Mount, t.Path)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("secret version check failed for %s/%s: %v", t.Mount, t.Path, err),
			})
			continue
		}
		if t.MaxVersions > 0 && info.MaxVersions < t.MaxVersions {
			alerts = append(alerts, Alert{
				Level: Warning,
				Message: fmt.Sprintf(
					"%s/%s: max_versions %d is below recommended %d",
					t.Mount, t.Path, info.MaxVersions, t.MaxVersions,
				),
			})
		}
		if t.MinVersionDrift > 0 {
			drift := info.CurrentVersion - info.OldestVersion
			if drift > t.MinVersionDrift {
				alerts = append(alerts, Alert{
					Level: Warning,
					Message: fmt.Sprintf(
						"%s/%s: version drift %d exceeds threshold %d",
						t.Mount, t.Path, drift, t.MinVersionDrift,
					),
				})
			}
		}
	}
	return alerts, nil
}
