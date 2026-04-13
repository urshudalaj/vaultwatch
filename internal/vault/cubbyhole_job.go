package monitor

import (
	"fmt"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

// CubbyholeChecker defines the interface for listing cubbyhole keys.
type cubbyholeChecker interface {
	ListCubbyholeKeys(path string) ([]string, error)
}

// CubbyholeJob checks cubbyhole paths for expected keys and alerts when they are missing.
type CubbyholeJob struct {
	checker       cubbyholeChecker
	paths         []string
	expectedKeys  map[string][]string
}

// NewCubbyholeJob creates a new CubbyholeJob.
func NewCubbyholeJob(checker cubbyholeChecker, paths []string, expectedKeys map[string][]string) *CubbyholeJob {
	return &CubbyholeJob{
		checker:      checker,
		paths:        paths,
		expectedKeys: expectedKeys,
	}
}

// Run executes the cubbyhole job and returns any alerts.
func (j *CubbyholeJob) Run() []monitor.Alert {
	var alerts []monitor.Alert

	for _, path := range j.paths {
		keys, err := j.checker.ListCubbyholeKeys(path)
		if err != nil {
			alerts = append(alerts, monitor.Alert{
				Level:   monitor.Critical,
				Message: fmt.Sprintf("cubbyhole: failed to list keys at %q: %v", path, err),
			})
			continue
		}

		if len(keys) == 0 {
			alerts = append(alerts, monitor.Alert{
				Level:   monitor.Warning,
				Message: fmt.Sprintf("cubbyhole: no keys found at path %q", path),
			})
			continue
		}

		expected, ok := j.expectedKeys[path]
		if !ok {
			continue
		}

		keySet := make(map[string]struct{}, len(keys))
		for _, k := range keys {
			keySet[k] = struct{}{}
		}

		for _, exp := range expected {
			if _, found := keySet[exp]; !found {
				alerts = append(alerts, monitor.Alert{
					Level:   monitor.Warning,
					Message: fmt.Sprintf("cubbyhole: expected key %q missing at path %q", exp, path),
				})
			}
		}
	}

	return alerts
}
