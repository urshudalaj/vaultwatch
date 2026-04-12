package monitor

import (
	"context"
	"fmt"
	"time"
)

// TokenExpiryChecker is implemented by anything that can return token metadata.
type TokenExpiryChecker interface {
	LookupSelf(ctx context.Context) (TokenExpiryInfo, error)
}

// TokenExpiryInfo carries the fields needed for expiry evaluation.
type TokenExpiryInfo struct {
	DisplayName string
	ExpireTime  time.Time
	Renewable   bool
	TTL         int
}

// TokenExpiryJob raises alerts when the current Vault token is close to expiry.
type TokenExpiryJob struct {
	checker         TokenExpiryChecker
	warningThreshold time.Duration
}

// NewTokenExpiryJob constructs a TokenExpiryJob.
 warningThreshold is the TTL remaining below which a warning alert is raised.
func NewTokenExpiryJob(checker TokenExpiryChecker, warningThreshold time.Duration) *TokenExpiryJob {
	return &TokenExpiryJob{checker: checker, warningThreshold: warningThreshold}
}

// Run evaluates the token TTL and returns any alerts.
func (j *TokenExpiryJob) Run(ctx context.Context) ([]Alert, error) {
	info, err := j.checker.LookupSelf(ctx)
	if err != nil {
		return nil, fmt.Errorf("token expiry job: lookup: %w", err)
	}

	// Root tokens have no expiry.
	if info.ExpireTime.IsZero() {
		return nil, nil
	}

	remaining := time.Until(info.ExpireTime)

	if remaining <= 0 {
		return []Alert{{
			Level:   Critical,
			Message: fmt.Sprintf("token '%s' has expired", info.DisplayName),
		}}, nil
	}

	if remaining <= j.warningThreshold {
		return []Alert{{
			Level:   Warning,
			Message: fmt.Sprintf("token '%s' expires in %s", info.DisplayName, formatDuration(remaining)),
		}}, nil
	}

	return nil, nil
}
