package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nextgridit-team/Aegis-WAF/internal/app"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		addr := os.Getenv("MANAGEMENT_ADDR")
		if addr == "" {
			addr = ":9090"
		}
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			os.Exit(1)
		}
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		client := http.Client{Timeout: 2 * time.Second}
		r, e := client.Get("http://" + net.JoinHostPort(host, port) + "/readyz")
		if e != nil {
			os.Exit(1)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	if e := run(); e != nil {
		slog.Error(e.Error())
		os.Exit(1)
	}
}
func run() error {
	cfg, e := app.LoadConfig()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a, e := app.New(ctx, cfg)
	if e != nil {
		return e
	}
	defer a.Close()
	var wg sync.WaitGroup
	var servers []*http.Server
	var listeners []net.Listener
	for i, addr := range []string{cfg.HTTPAddr, cfg.HTTPSAddr, cfg.ManagementAddr} {
		l, e := net.Listen("tcp", addr)
		if e != nil {
			for _, old := range listeners {
				old.Close()
			}
			return fmt.Errorf("listen on %s: %w", addr, e)
		}
		listeners = append(listeners, l)
		var handler http.Handler = http.HandlerFunc(a.Public)
		if i == 2 {
			handler = a.Management()
		}
		s := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
		if i == 1 {
			s.TLSConfig = a.TLSConfig()
			s.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
		}
		servers = append(servers, s)
	}
	wg.Add(2)
	go func() { defer wg.Done(); a.Background(ctx) }()
	go func() { defer wg.Done(); a.ACMEWorker(ctx) }()
	errs := make(chan error, 3)
	for i, s := range servers {
		go func(i int, s *http.Server) {
			var e error
			if i == 1 {
				e = s.ServeTLS(listeners[i], "", "")
			} else {
				e = s.Serve(listeners[i])
			}
			if !errors.Is(e, http.ErrServerClosed) {
				errs <- e
			}
		}(i, s)
	}
	slog.Info("listeners started", "http", cfg.HTTPAddr, "https", cfg.HTTPSAddr, "management", cfg.ManagementAddr)
	select {
	case <-ctx.Done():
	case e = <-errs:
		cancel()
	}
	drain, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	for _, s := range servers {
		if er := s.Shutdown(drain); er != nil {
			s.Close()
		}
	}
	cancel()
	wg.Wait()
	if e != nil && !strings.Contains(e.Error(), "closed network connection") {
		return e
	}
	return nil
}
