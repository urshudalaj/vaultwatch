package monitor

// captureAlertSink records all alerts sent to it during tests.
type captureAlertSink struct {
	alerts []Alert
}

func (c *captureAlertSink) Send(a Alert) {
	c.alerts = append(c.alerts, a)
}

// AlertSink is the minimal interface expected by jobs that emit alerts.
// It is declared here so test helpers in this package can satisfy it without
// importing the notifier package.
type AlertSink interface {
	Send(Alert)
}
