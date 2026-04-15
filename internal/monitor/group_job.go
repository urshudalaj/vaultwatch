package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// GroupTarget identifies an identity group to monitor.
type GroupTarget struct {
	ID   string
	Name string // human-readable label for alerts
}

// groupChecker is the interface satisfied by vault.GroupChecker.
type groupChecker interface {
	GetGroup(id string) (*vault.GroupInfo, error)
}

// GroupJob checks identity groups for disabled state or missing policies.
type GroupJob struct {
	checker groupChecker
	targets []GroupTarget
	notify  func(Alert)
}

// NewGroupJob constructs a GroupJob.
func NewGroupJob(checker groupChecker, targets []GroupTarget, notify func(Alert)) *GroupJob {
	return &GroupJob{checker: checker, targets: targets, notify: notify}
}

// Run executes the group checks and fires alerts where needed.
func (j *GroupJob) Run(ctx context.Context) error {
	for _, t := range j.targets {
		info, err := j.checker.GetGroup(t.ID)
		if err != nil {
			j.notify(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("group %s (%s): lookup failed: %v", t.Name, t.ID, err),
			})
			continue
		}

		if info.Disabled {
			j.notify(Alert{
				Level:   LevelCritical,
				Message: fmt.Sprintf("group %s (%s) is disabled", t.Name, t.ID),
			})
		}

		if len(info.Policies) == 0 {
			j.notify(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("group %s (%s) has no policies attached", t.Name, t.ID),
			})
		}
	}
	return nil
}
