package scheduler

import (
	"context"
	"log"
	"time"
)

// FuncRunner is a lightweight scheduler that calls an arbitrary function
// on each tick. It is primarily used in tests and simple integrations where
// full Monitor/Notifier/Reporter wiring is not needed.
type FuncRunner struct {
	fn       func(context.Context)
	interval time.Duration
}

// NewFunc creates a FuncRunner that invokes fn immediately and then on every
// interval tick until the context is cancelled.
func NewFunc(fn func(context.Context), interval time.Duration) *FuncRunner {
	return &FuncRunner{fn: fn, interval: interval}
}

// Run starts the FuncRunner loop. It blocks until ctx is cancelled.
func (f *FuncRunner) Run(ctx context.Context) {
	log.Printf("scheduler: func-runner starting with interval %s", f.interval)
	f.fn(ctx)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.fn(ctx)
		case <-ctx.Done():
			log.Println("scheduler: func-runner shutting down")
			return
		}
	}
}
