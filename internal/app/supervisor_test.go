package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPanicIsContainedAndRestarted(t *testing.T) {
	a := &App{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var runs atomic.Int64
	cleaned := atomic.Bool{}
	a.RunWorker(ctx, "test", func(context.Context) {
		defer cleaned.Store(true)
		if runs.Add(1) == 1 {
			panic("sensitive details must not be logged")
		}
	})
	if runs.Load() != 2 || a.workerPanics.Load() != 1 || !cleaned.Load() {
		t.Fatal("worker did not recover and restart safely")
	}
}
func TestWorkerPanicBackoffStopsWithContext(t *testing.T) {
	a := &App{}
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	a.RunWorker(ctx, "test", func(context.Context) { cancel(); panic("test") })
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("worker ignored cancellation")
	}
}
