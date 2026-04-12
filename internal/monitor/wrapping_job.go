package monitor

import (
	"context"
	"fmt"
	"log"
)

// WrappingTokenProvider is satisfied by vault.WrappingChecker.
type WrappingTokenProvider interface {
	LookupWrappingToken(ctx context.Context, wrappingToken string) (interface{ GetTTL() int }, error)
}

// wrappingLookup is the minimal interface used by NewWrappingJob.
type wrappingLookup interface {
	LookupWrappingToken(ctx context.Context, token string) (ttl int, creationPath string, err error)
}

// WrappingJob checks a set of wrapping tokens and alerts when their TTL is low.
type WrappingJob struct {
	checker        wrappingLookup
	tokens         []string
	warnThresholdS int
	alerts         chan Alert
}

// NewWrappingJob constructs a WrappingJob.
func NewWrappingJob(checker wrappingLookup, tokens []string, warnThresholdSeconds int, alerts chan Alert) *WrappingJob {
	return &WrappingJob{
		checker:        checker,
		tokens:         tokens,
		warnThresholdS: warnThresholdSeconds,
		alerts:         alerts,
	}
}

// Run inspects each wrapping token and emits an alert if TTL is below the threshold.
func (j *WrappingJob) Run(ctx context.Context) {
	for _, tok := range j.tokens {
		ttl, path, err := j.checker.LookupWrappingToken(ctx, tok)
		if err != nil {
			log.Printf("wrapping_job: lookup failed for token: %v", err)
			continue
		}

		if ttl <= 0 {
			j.alerts <- Alert{
				Level:   Critical,
				Message: fmt.Sprintf("wrapping token for path %q has expired (TTL=%d)", path, ttl),
			}
			continue
		}

		if ttl <= j.warnThresholdS {
			j.alerts <- Alert{
				Level:   Warning,
				Message: fmt.Sprintf("wrapping token for path %q expiring soon (TTL=%ds)", path, ttl),
			}
		}
	}
}
