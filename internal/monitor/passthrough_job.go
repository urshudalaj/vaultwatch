package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// PassthroughTarget describes a passthrough (generic) mount to evaluate.
type PassthroughTarget struct {
	Mount      string
	MinTTL     int // minimum acceptable default_ttl in seconds
	MinMaxTTL  int // minimum acceptable max_ttl in seconds
}

// passthroughChecker is the interface satisfied by vault.PassthroughChecker.
type passthroughChecker interface {
	GetMount(mount string) (*vault.PassthroughInfo, error)
}

// NewPassthroughJob returns a JobFunc that checks passthrough mount tuning and
// emits alerts when TTL values fall below configured thresholds.
func NewPassthroughJob(checker passthroughChecker, targets []PassthroughTarget) JobFunc {
	return func(ctx context.Context) ([]Alert, error) {
		var alerts []Alert

		for _, t := range targets {
			info, err := checker.GetMount(t.Mount)
			if err != nil {
				alerts = append(alerts, Alert{
					Level:   Critical,
					Message: fmt.Sprintf("passthrough: failed to read mount %q: %v", t.Mount, err),
				})
				continue
			}

			if t.MinTTL > 0 && info.DefaultTTL < t.MinTTL {
				alerts = append(alerts, Alert{
					Level: Warning,
					Message: fmt.Sprintf(
						"passthrough: mount %q default_ttl %ds is below minimum %ds",
						t.Mount, info.DefaultTTL, t.MinTTL,
					),
				})
			}

			if t.MinMaxTTL > 0 && info.MaxTTL < t.MinMaxTTL {
				alerts = append(alerts, Alert{
					Level: Warning,
					Message: fmt.Sprintf(
						"passthrough: mount %q max_ttl %ds is below minimum %ds",
						t.Mount, info.MaxTTL, t.MinMaxTTL,
					),
				})
			}
		}

		return alerts, nil
	}
}
