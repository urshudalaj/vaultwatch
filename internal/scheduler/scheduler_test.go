package scheduler_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/scheduler"
)

// tickRecorder counts how many times its Run method is invoked via a stub.
type stubRunner struct {
	calls atomic.Int32
}

func (s *stubRunner) increment() { s.calls.Add(1) }
func (s *stubRunner) count() int  { return int(s.calls.Load()) }

func TestRun_ExecutesImmediately(t *testing.T) {
	called := make(chan struct{}, 5)

	// Use a short interval and a context that cancels quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_ = scheduler.NewFunc(func(_ context.Context) {
		called <- struct{}{}
	}, 1*time.Hour) // long interval — only first immediate call expected

	// We cannot call Run directly without real deps; test via NewFunc helper.
	// This test validates that at least one call is dispatched before interval.
	runner := scheduler.NewFunc(func(_ context.Context) {
		called <- struct{}{}
	}, 1*time.Hour)

	go runner.Run(ctx)

	select {
	case <-called:
		// success: immediate execution confirmed
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected immediate execution but timed out")
	}
}

func TestRun_TicksOnInterval(t *testing.T) {
	var count atomic.Int32

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	runner := scheduler.NewFunc(func(_ context.Context) {
		count.Add(1)
	}, 100*time.Millisecond)

	go runner.Run(ctx)

	<-ctx.Done()
	time.Sleep(20 * time.Millisecond) // allow final goroutine to settle

	// With 350ms timeout and 100ms interval: immediate + ~3 ticks = 4 calls.
	got := int(count.Load())
	if got < 3 {
		t.Errorf("expected at least 3 executions, got %d", got)
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	var count atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())

	runner := scheduler.NewFunc(func(_ context.Context) {
		count.Add(1)
	}, 50*time.Millisecond)

	done := make(chan struct{})
	go func() {
		runner.Run(ctx)
		close(done)
	}()

	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run returned after cancel — correct
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not stop after context cancellation")
	}
}
