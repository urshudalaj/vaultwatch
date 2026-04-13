package monitor

import (
	"context"
	"fmt"
	"time"
)

// ACLAccessorLookup is the interface for looking up token accessor info.
type ACLAccessorLookup interface {
	LookupAccessor(accessor string) (*ACLInfo, error)
}

// ACLInfo mirrors vault.ACLInfo for use in the monitor package.
type ACLInfo struct {
	Accessor    string
	DisplayName string
	Policies    []string
	Orphan      bool
	ExpireTime  string
}

// ACLJob checks token accessors for missing policies or imminent expiry.
type ACLJob struct {
	checker   ACLAccessorLookup
	accessors []string
	notifier  Notifier
	warnBefore time.Duration
}

// NewACLJob creates a new ACLJob.
func NewACLJob(checker ACLAccessorLookup, accessors []string, notifier Notifier, warnBefore time.Duration) *ACLJob {
	return &ACLJob{
		checker:    checker,
		accessors:  accessors,
		notifier:   notifier,
		warnBefore: warnBefore,
	}
}

// Run executes the ACL accessor check job.
func (j *ACLJob) Run(ctx context.Context) error {
	for _, acc := range j.accessors {
		info, err := j.checker.LookupAccessor(acc)
		if err != nil {
			continue
		}

		if len(info.Policies) == 0 {
			alert := Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("ACL accessor %s (%s) has no policies attached", acc, info.DisplayName),
			}
			_ = j.notifier.Send(ctx, alert)
			continue
		}

		if info.ExpireTime != "" {
			expiry, err := time.Parse(time.RFC3339, info.ExpireTime)
			if err == nil && time.Until(expiry) < j.warnBefore {
				alert := Alert{
					Level:   LevelCritical,
					Message: fmt.Sprintf("ACL accessor %s (%s) expires at %s", acc, info.DisplayName, info.ExpireTime),
				}
				_ = j.notifier.Send(ctx, alert)
			}
		}
	}
	return nil
}
