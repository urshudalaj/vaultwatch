package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// ResponseWrappingLookup is the interface used by ResponseWrappingJob.
type ResponseWrappingLookup interface {
	Lookup(ctx context.Context, token string) (*vault.ResponseWrappingInfo, error)
}

// ResponseWrappingJob checks that a response-wrapping token has not expired
// and alerts when its remaining TTL falls below a threshold.
type ResponseWrappingJob struct {
	checker       ResponseWrappingLookup
	wrappingToken string
	warnThreshold time.Duration
}

// NewResponseWrappingJob creates a ResponseWrappingJob.
func NewResponseWrappingJob(checker ResponseWrappingLookup, wrappingToken string, warnThreshold time.Duration) *ResponseWrappingJob {
	if warnThreshold <= 0 {
		warnThreshold = 5 * time.Minute
	}
	return &ResponseWrappingJob{
		checker:       checker,
		wrappingToken: wrappingToken,
		warnThreshold: warnThreshold,
	}
}

// Run executes the response-wrapping token check and returns any alerts.
func (j *ResponseWrappingJob) Run(ctx context.Context) ([]Alert, error) {
	info, err := j.checker.Lookup(ctx, j.wrappingToken)
	if err != nil {
		return []Alert{{
			Level:   AlertLevelCritical,
			Message: fmt.Sprintf("response wrapping lookup failed: %v", err),
		}}, nil
	}

	expiry := info.CreationTime.Add(time.Duration(info.TTL) * time.Second)
	remaining := time.Until(expiry)

	if remaining <= 0 {
		return []Alert{{
			Level:   AlertLevelCritical,
			Message: fmt.Sprintf("response wrapping token for path %q has expired", info.CreationPath),
		}}, nil
	}

	if remaining < j.warnThreshold {
		return []Alert{{
			Level:   AlertLevelWarning,
			Message: fmt.Sprintf("response wrapping token for path %q expires in %s", info.CreationPath, remaining.Round(time.Second)),
		}}, nil
	}

	return nil, nil
}
