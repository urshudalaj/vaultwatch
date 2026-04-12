package monitor

// recordingSink captures alerts emitted during a job run.
// Reused across multiple job test files in this package.
type recordingSink struct {
	alerts []Alert
}

func (r *recordingSink) Send(a Alert) {
	r.alerts = append(r.alerts, a)
}
