package app

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

func (a *App) logEarlyRequest(r *http.Request, started time.Time, status int, source, signal string) {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	event := accessEvent{at: time.Now(), host: truncateUTF8(requestHost(r.Host), 253), method: r.Method, status: status, duration: time.Since(started).Milliseconds(), peer: peer, responseSource: source, blocked: signal != ""}
	if signal != "" {
		event.signals = []string{signal}
	}
	select {
	case a.access <- event:
	default:
		a.dropped.Add(1)
		a.stdoutDropped.Add(1)
	}
}

func (a *App) logWorker(ctx context.Context) { a.runAccessLogger(ctx, a.storeAccessBatch) }

// Stdout is the first sink. A separate bounded queue isolates it from slow or
// unavailable PostgreSQL writes. Neither stage runs on the forwarding goroutine.
func (a *App) runAccessLogger(ctx context.Context, store func(context.Context, []accessEvent) error) {
	batches := make(chan []accessEvent, 8)
	writerCtx, stopWriter := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.RunWorker(writerCtx, "access-database", func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				case batch, ok := <-batches:
					if !ok {
						return
					}
					func() {
						persisted := false
						defer func() {
							if !persisted {
								a.dropped.Add(uint64(len(batch)))
							}
						}()
						work, cancel := context.WithTimeout(ctx, 3*time.Second)
						defer cancel()
						if err := store(work, batch); err == nil {
							persisted = true
						}
					}()
				}
			}
		})
	}()
	defer func() {
		close(batches)
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			stopWriter()
			<-done
		}
		stopWriter()
		for batch := range batches {
			a.dropped.Add(uint64(len(batch)))
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batch := make([]accessEvent, 0, 1000)
	defer func() {
		a.dropped.Add(uint64(len(batch)))
		a.stdoutDropped.Add(uint64(len(batch)))
		for _, event := range batch {
			if event.releaseEvidence != nil {
				event.releaseEvidence()
			}
		}
	}()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for n := range batch {
			batch[n].enrich()
			if batch[n].requestID == "" {
				batch[n].requestID = token()
			}
			batch[n].stdoutEmitted = emitSecurityEvent(slog.Default(), batch[n]) == nil
			if !batch[n].stdoutEmitted {
				a.stdoutDropped.Add(1)
			}
		}
		select {
		case batches <- batch:
		default:
			a.dropped.Add(uint64(len(batch)))
		}
		batch = make([]accessEvent, 0, 1000)
	}
	for {
		select {
		case event := <-a.access:
			batch = append(batch, event)
			if len(batch) == 1000 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case event := <-a.access:
					batch = append(batch, event)
					if len(batch) == 1000 {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}
