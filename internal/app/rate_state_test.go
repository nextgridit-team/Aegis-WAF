package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sharedTestSettings(t *testing.T) rateStateSettings {
	t.Helper()
	address := os.Getenv("TEST_REDIS_ADDRESS")
	if address == "" {
		t.Skip("set TEST_REDIS_ADDRESS for real Redis/Dragonfly tests")
	}
	return rateStateSettings{Backend: "redis", Address: address, TimeoutMS: 250}
}
func TestRateStateValidation(t *testing.T) {
	for _, s := range []rateStateSettings{{Backend: "other"}, {Backend: "redis", Address: "redis://user:secret@server:6379"}, {Backend: "redis", Address: "server:0"}, {Backend: "redis", Address: "server:65536"}, {Backend: "redis", Address: "server:6379", TimeoutMS: 251}, {Backend: "redis", Address: "server:6379", Username: "bad\nuser"}} {
		if _, e := normalizeRateState(s); e == nil {
			t.Fatal("accepted invalid backend", s.Backend)
		}
	}
}
func TestSharedRateStateIntegration(t *testing.T) {
	settings := sharedTestSettings(t)
	a, b, api, site, forwarded := captchaFixture(t)
	p := defaultProtection()
	p.Mode = "block"
	p.RequestsPerSecond = 1
	p.Burst = 3
	p.SiteRequestsPerSecond = 1000
	p.SiteBurst = 1000
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	var status struct {
		Revision int64 `json:"revision"`
	}
	json.Unmarshal(api.call("GET", "/api/rate-state", nil, 200), &status)
	input := rateStateInput{rateStateSettings: settings, Revision: status.Revision, Password: os.Getenv("TEST_REDIS_PASSWORD")}
	api.call("POST", "/api/rate-state/test", input, 200)
	api.call("PUT", "/api/rate-state", input, 200)
	readback := api.call("GET", "/api/rate-state", nil, 200)
	if input.Password != "" && bytes.Contains(readback, []byte(input.Password)) {
		t.Fatal("password read back")
	}
	for _, app := range []*App{a, b} {
		if e := app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	runtime := a.active.Load().rateState
	if runtime == nil || runtime.stored.Settings.Backend != "redis" {
		t.Fatal("backend not active")
	}
	var cipher []byte
	a.db.QueryRow(context.Background(), "SELECT password_cipher FROM rate_state WHERE id").Scan(&cipher)
	if input.Password != "" && bytes.Contains(cipher, []byte(input.Password)) {
		t.Fatal("plaintext rate-state password")
	}
	request := func(app *App, ua string) int {
		r := httptest.NewRequest("GET", "http://bot.test/", nil)
		r.RemoteAddr = "198.51.100.44:1234"
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		app.Public(w, r)
		<-app.access
		return w.Code
	}
	for i, app := range []*App{a, b, a, b} {
		want := 200
		if i == 3 {
			want = 429
		}
		if got := request(app, "browser"); got != want {
			t.Fatalf("replica shared budget %d: got %d want %d", i, got, want)
		}
	}
	if forwarded.Load() != 3 {
		t.Fatal("exceeded shared forwarding budget", forwarded.Load())
	}
	// Concurrent calls through independently pooled clients cannot multiply a
	// fresh namespace's budget. Allow server-time refill only if the test is slow.
	stored := runtime.stored
	stored.Namespace = token()
	stored.Revision++
	first, e := a.compileRateState(stored)
	if e != nil {
		t.Fatal(e)
	}
	defer first.retire()
	second, e := b.compileRateState(stored)
	if e != nil {
		t.Fatal(e)
	}
	defer second.retire()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state := first
			if i%2 != 0 {
				state = second
			}
			decisions, e := state.Take(context.Background(), []rateLimit{{rateKey{site, "concurrent"}, 1, 5}}, time.Now())
			if e != nil {
				t.Error(e)
				return
			}
			if decisions[0] {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	maximum := 5 + int(time.Since(start).Seconds())
	if allowed.Load() < 5 || int(allowed.Load()) > maximum {
		t.Fatal("non-atomic distributed budget", allowed.Load(), maximum)
	}
	// Keys use hashed client identities; the backend does not store raw IPs.
	client, release := first.acquire()
	defer release()
	keys, e := client.Keys(context.Background(), "aegis:{"+stored.Namespace+"}:rates:*").Result()
	if e != nil || len(keys) != 2 {
		t.Fatal("unexpected namespace keys", len(keys), e)
	}
	for _, key := range keys {
		if strings.Contains(key, "concurrent") {
			t.Fatal("raw client identity in backend key")
		}
	}
	for _, key := range keys {
		if !strings.HasSuffix(key, "registry") {
			ttl, e := client.PTTL(context.Background(), key).Result()
			if e != nil || ttl < 5*time.Second || ttl > 66*time.Second {
				t.Fatal("unsafe bucket TTL", ttl, e)
			}
		}
	}
	registry := "aegis:{" + stored.Namespace + "}:rates:registry"
	_, e = client.Eval(context.Background(), `for i=1,100000 do redis.call('ZADD',KEYS[1],1e15,'capacity:'..i) end return 1`, []string{registry}).Result()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = second.Take(context.Background(), []rateLimit{{rateKey{site, "capacity-test"}, 1, 1}}, time.Now()); e == nil {
		t.Fatal("shared bucket capacity was not bounded")
	}
	if e = client.Del(context.Background(), registry).Err(); e != nil {
		t.Fatal(e)
	}
	// Retired snapshots can finish a late-acquired operation without closing an
	// active client's connection; their pool closes again after release.
	first.retire()
	if _, e = first.Take(context.Background(), []rateLimit{{rateKey{site, "late"}, 1, 1}}, time.Now()); e != nil {
		t.Fatal("retired snapshot broke late request", e)
	}
	// Missing shared state fails closed instead of returning to local budgets.
	input.Revision++
	input.Address = "127.0.0.1:1"
	input.Password = ""
	input.ClearPassword = true
	api.call("PUT", "/api/rate-state", input, 200)
	for _, app := range []*App{a, b} {
		if e := app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if got := request(a, "browser"); got != 503 {
		t.Fatal("backend outage did not fail closed", got)
	}
	p.Mode = "observe"
	p.BotMode = "block"
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if got := request(a, "sqlmap"); got != 403 {
		t.Fatal("Observe outage bypassed independent anti-bot", got)
	}
	p.Mode = "off"
	p.BotChallenge.Enabled = true
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	a.refresh(context.Background())
	if got := request(a, "browser"); got != 503 {
		t.Fatal("bot-frequency backend outage failed open", got)
	}
	// Restoring the original endpoint recovers without a process restart.
	input.Revision++
	input.rateStateSettings = settings
	input.Password = os.Getenv("TEST_REDIS_PASSWORD")
	input.ClearPassword = false
	api.call("POST", "/api/rate-state/test", input, 200)
	api.call("PUT", "/api/rate-state", input, 200)
	p.BotMode = "off"
	p.BotChallenge.Enabled = false
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	a.refresh(context.Background())
	if got := request(a, "browser"); got != 200 {
		t.Fatal("backend did not recover", got)
	}
	sealed, e := a.archiveSnapshot(a.active.Load(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	restoredApp := &App{cfg: a.cfg}
	restored, e := restoredApp.decodeSnapshot(sealed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.rateState.retire()
	if restored.rateState == nil || restored.rateState.stored.Settings.Address != settings.Address || restored.rateState.password != os.Getenv("TEST_REDIS_PASSWORD") {
		t.Fatal("sealed recovery lost configured shared state")
	}
	// Tampered stored ciphertext must preserve the last working snapshot.
	old := a.active.Load()
	a.db.Exec(context.Background(), "UPDATE rate_state SET password_cipher='broken'::bytea; UPDATE config_version SET version=version+1 WHERE id")
	if e := a.refresh(context.Background()); e == nil || a.active.Load() != old {
		t.Fatal("invalid backend config replaced working snapshot")
	}
}
func TestSharedBotFrequencyAcrossReplicas(t *testing.T) {
	settings := sharedTestSettings(t)
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	cipher, e := seal(cfg.Key, cfg.KeyID+":rate-state-password", []byte(os.Getenv("TEST_REDIS_PASSWORD")))
	if e != nil {
		t.Fatal(e)
	}
	stored := storedRateState{Settings: settings, Namespace: token(), Cipher: cipher, KeyID: cfg.KeyID, Revision: 1}
	first, _ := a.compileRateState(stored)
	second, _ := b.compileRateState(stored)
	defer first.retire()
	defer second.retire()
	p := defaultProtection()
	p.BotChallenge.Enabled = true
	p.BotMode = "block"
	p.BotChallenge.RequestsPerSecond = 1
	p.BotChallenge.Burst = 1
	policy, e := compileProtection(p)
	if e != nil {
		t.Fatal(e)
	}
	ip := netip.MustParseAddr("198.51.100.4")
	r := httptest.NewRequest("GET", "https://bot.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en")
	one := a.botScore(policy, 1, r.WithContext(context.WithValue(r.Context(), rateStateKey{}, first)), ip, time.Now())
	two := b.botScore(policy, 1, r.WithContext(context.WithValue(r.Context(), rateStateKey{}, second)), ip, time.Now())
	if one.StateUnavailable || one.Score != 0 || two.StateUnavailable || two.Score != 40 {
		t.Fatal("frequency did not share budget", one, two)
	}
}

func TestRateStateTLSAndCredentialChanges(t *testing.T) {
	a := &App{cfg: Config{Key: bytes.Repeat([]byte{1}, 32), KeyID: "test"}}
	cipher, e := seal(a.cfg.Key, "test:rate-state-password", []byte("test-only-secret"))
	if e != nil {
		t.Fatal(e)
	}
	stored := storedRateState{Settings: rateStateSettings{Backend: "redis", Address: "redis.example.test:6379", TLS: true}, Cipher: cipher, KeyID: "test", Namespace: "test-namespace", Revision: 1}
	state, e := a.compileRateState(stored)
	if e != nil {
		t.Fatal(e)
	}
	client := state.newClient()
	defer client.Close()
	tls := client.Options().TLSConfig
	if tls == nil || tls.InsecureSkipVerify || tls.ServerName != "redis.example.test" || client.Options().DialerRetries != 1 {
		t.Fatal("unsafe backend TLS/retry defaults")
	}
	changed := rateStateInput{rateStateSettings: stored.Settings, Revision: 1}
	changed.Address = "other.example.test:6379"
	if _, e = a.candidateRateState(stored, changed); e == nil {
		t.Fatal("credentials reused at another endpoint")
	}
	changed.ClearPassword = true
	if candidate, e := a.candidateRateState(stored, changed); e != nil || len(candidate.Cipher) != 0 {
		t.Fatal("explicit credential clear failed", e)
	}
	stored.Cipher[0] ^= 1
	if _, e = a.compileRateState(stored); e == nil {
		t.Fatal("unauthenticated credential ciphertext accepted")
	}
}
