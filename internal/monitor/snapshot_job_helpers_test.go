package monitor

import (
	"context"
)

// recordingNotifier captures alerts sent during tests.
// It is shared across multiple job test files in this package.
type recordingNotifier struct {
	alerts []Alert
}

func (r *recordingNotifier) Send(_ context.Context, a Alert) error {
	r.alerts = append(r.alerts, a)
	return nil
}
