package monitor

import (
	"fmt"
	"time"
)

// TokenTTLTarget describes a token accessor to monitor.
type TokenTTLTarget struct {
	Accessor    string
	DisplayName string
	WarnBefore  time.Duration
}

// TokenTTLLookup is satisfied by vault.TokenTTLChecker.
type TokenTTLLookup interface {
	LookupTokenTTL(accessor string) (*TokenTTLInfoResult, error)
}

// TokenTTLInfoResult mirrors vault.TokenTTLInfo to avoid import cycle in tests.
type TokenTTLInfoResult struct {
	TTL         int
	CreationTTL int
	DisplayName string
	ExpireTime  string
}

// TokenTTLJob monitors token TTLs via accessor and emits alerts when expiry is near.
type TokenTTLJob struct {
	checker TokenTTLLookup
	targets []TokenTTLTarget
	notify  func(Alert)
}

// NewTokenTTLJob creates a TokenTTLJob.
func NewTokenTTLJob(checker TokenTTLLookup, targets []TokenTTLTarget, notify func(Alert)) *TokenTTLJob {
	return &TokenTTLJob{checker: checker, targets: targets, notify: notify}
}

// Run executes the TTL check for all configured targets.
func (j *TokenTTLJob) Run() {
	for _, t := range j.targets {
		info, err := j.checker.LookupTokenTTL(t.Accessor)
		if err != nil {
			j.notify(Alert{
				Level:   Critical,
				Message: fmt.Sprintf("token TTL lookup failed for accessor %q: %v", t.Accessor, err),
			})
			continue
		}

		remaining := time.Duration(info.TTL) * time.Second
		warnBefore := t.WarnBefore
		if warnBefore == 0 {
			warnBefore = 24 * time.Hour
		}

		name := t.DisplayName
		if name == "" {
			name = info.DisplayName
		}
		if name == "" {
			name = t.Accessor
		}

		if remaining <= 0 {
			j.notify(Alert{
				Level:   Critical,
				Message: fmt.Sprintf("token %q has expired (accessor: %s)", name, t.Accessor),
			})
		} else if remaining < warnBefore {
			j.notify(Alert{
				Level:   Warning,
				Message: fmt.Sprintf("token %q expires in %s (accessor: %s)", name, remaining.Round(time.Second), t.Accessor),
			})
		}
	}
}
