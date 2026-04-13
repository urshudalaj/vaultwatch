package monitor

import (
	"context"
	"fmt"
)

// ControlGroupChecker is the interface for checking control group requests.
type ControlGroupChecker interface {
	CheckRequest(ctx context.Context, accessor string) (interface{ IsApproved() bool; GetID() string }, error)
}

// controlGroupChecker is a typed interface used internally.
type cgChecker interface {
	CheckRequest(ctx context.Context, accessor string) (*cgResult, error)
}

type cgResult struct {
	ID       string
	Approved bool
	Path     string
}

// ControlGroupJob monitors pending control group requests.
type ControlGroupJob struct {
	checker  cgChecker
	accessors []string
}

// NewControlGroupJob creates a ControlGroupJob for the given accessors.
func NewControlGroupJob(checker cgChecker, accessors []string) *ControlGroupJob {
	return &ControlGroupJob{checker: checker, accessors: accessors}
}

// Run checks each accessor and returns alerts for unapproved requests.
func (j *ControlGroupJob) Run(ctx context.Context) ([]Alert, error) {
	var alerts []Alert
	for _, acc := range j.accessors {
		if acc == "" {
			continue
		}
		result, err := j.checker.CheckRequest(ctx, acc)
		if err != nil {
			alerts = append(alerts, Alert{
				Level:   Critical,
				Message: fmt.Sprintf("control group check failed for accessor %s: %v", acc, err),
			})
			continue
		}
		if !result.Approved {
			alerts = append(alerts, Alert{
				Level:   Warning,
				Message: fmt.Sprintf("control group request %s for path %s is not yet approved", result.ID, result.Path),
			})
		}
	}
	return alerts, nil
}
