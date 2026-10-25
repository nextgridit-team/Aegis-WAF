package app

import (
	"context"
	"log/slog"
	"time"
)

// RunWorker keeps a background worker panic from taking down public listeners.
// Worker functions must defer rollback/lock release and tolerate restarting.
func (a *App) RunWorker(ctx context.Context, name string, run func(context.Context)) {
	for ctx.Err() == nil {
		failed := false
		func() {
			defer func() {
				if recover() != nil {
					failed = true
					a.workerPanics.Add(1)
					slog.Error("background worker panicked; restarting", "worker", name)
				}
			}()
			run(ctx)
		}()
		if !failed {
			return
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
