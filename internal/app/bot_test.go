package app

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBotSuspicionAndDefaults(t *testing.T) {
	for _, bad := range []botChallengeSettings{{Threshold: 101}, {Threshold: -1}, {ClearanceMinutes: 121}, {RequestsPerSecond: 50, Burst: 1}} {
		if _, e := normalizeBotChallenge(bad); e == nil {
			t.Fatal("accepted invalid settings", bad)
		}
	}
	settings := defaultProtection()
	settings.BotMode = "block"
	settings.BotChallenge.Enabled = true
	p, e := compileProtection(settings)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	ip := netip.MustParseAddr("198.51.100.2")
	ordinary := httptest.NewRequest("GET", "https://bot.test/", nil)
	ordinary.Header.Set("User-Agent", "Mozilla/5.0 Chrome/144")
	ordinary.Header.Set("Accept", "text/html")
	ordinary.Header.Set("Accept-Language", "en")
	if result := a.botScore(p, 1, ordinary, ip, time.Now()); result.Score != 0 {
		t.Fatal("ordinary browser flagged", result)
	}
	ordinary.Header.Set("User-Agent", "HeadlessChrome/144")
	if result := a.botScore(p, 1, ordinary, ip, time.Now()); result.Score < result.Threshold {
		t.Fatal("headless signal missing", result)
	}
	ordinary.Header.Set("User-Agent", "curl/8")
	if result := a.botScore(p, 1, ordinary, ip, time.Now()); result.Score != 0 {
		t.Fatal("ordinary API tool flagged", result)
	}
	p.BotChallenge.RequestsPerSecond = 1
	p.BotChallenge.Burst = 1
	ordinary.Header.Set("User-Agent", "Mozilla/5.0")
	ordinary.Header.Del("Accept")
	ordinary.Header.Del("Accept-Language")
	now := time.Now()
	a.botScore(p, 2, ordinary, ip, now)
	result := a.botScore(p, 2, ordinary, ip, now)
	if result.Score != 65 {
		t.Fatal("combined independent signals not scored", result)
	}
}

func captchaFixture(t *testing.T) (*App, *App, testAPI, int64, *atomic.Int64) {
	t.Helper()
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "captcha test password 123", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "captcha test password 123"}, 200), &login)
	api.csrf = login["csrf"]
	forwarded := &atomic.Int64{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if strings.Contains(r.Header.Get("Cookie"), "__Host-aegis_") {
			t.Error("gateway proof leaked upstream")
		}
		io.WriteString(w, "application")
	}))
	t.Cleanup(up.Close)
	p := defaultProtection()
	p.BotMode = "block"
	p.BotChallenge.Enabled = true
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Captcha app", "hostnames": []string{"bot.test"}, "upstream": up.URL, "enabled": true, "redirect_https": false, "protection": p}, 200))
	for _, app := range []*App{a, b} {
		if e := app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	return a, b, api, site, forwarded
}
func botProbe(t *testing.T, a *App, method, path, ua, form string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, accessEvent) {
	t.Helper()
	r := httptest.NewRequest(method, "https://bot.test"+path, strings.NewReader(form))
	r.TLS = &tls.ConnectionState{ServerName: "bot.test"}
	r.RemoteAddr = "198.51.100.5:3000"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en")
	if method == "POST" {
		r.Header.Set("Origin", "https://bot.test")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Public(w, r)
	select {
	case event := <-a.access:
		return w, event
	case <-time.After(time.Second):
		t.Fatal("missing access event")
	}
	return nil, accessEvent{}
}
func cookieNamed(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatal("missing cookie", name)
	return nil
}
func captchaAnswer(t *testing.T, a *App, cookie *http.Cookie) (botClaims, string) {
	t.Helper()
	data, e := base64.RawURLEncoding.DecodeString(cookie.Value)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := open(a.cfg.Key, a.cfg.KeyID+":bot-cookie-v1", data)
	if e != nil {
		t.Fatal(e)
	}
	var claims botClaims
	if e = json.Unmarshal(raw, &claims); e != nil {
		t.Fatal(e)
	}
	var encrypted []byte
	var keyID string
	if e = a.db.QueryRow(context.Background(), "SELECT answer_cipher,key_id FROM bot_challenges WHERE id=$1", claims.ID).Scan(&encrypted, &keyID); e != nil {
		t.Fatal(e)
	}
	digits, e := open(a.cfg.Key, keyID+":bot-answer:"+claims.ID+":"+claims.Scope, encrypted)
	if e != nil {
		t.Fatal(e)
	}
	for i := range digits {
		digits[i] += '0'
	}
	return claims, string(digits)
}
func TestCaptchaSelectiveCrossReplicaAndBoundaries(t *testing.T) {
	a, b, api, site, forwarded := captchaFixture(t)
	w, event := botProbe(t, a, "GET", "/", "Mozilla/5.0 Chrome/144", "")
	if w.Code != 200 || len(w.Result().Cookies()) != 0 || event.bot.Decision != "allow" {
		t.Fatalf("ordinary session challenged: %d %+v", w.Code, event.bot)
	}
	before := forwarded.Load()
	w, event = botProbe(t, a, "GET", "/products?q=chair", "HeadlessChrome/144", "")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Verify your request") || event.bot.Decision != "challenge" || !event.blocked || forwarded.Load() != before {
		t.Fatal("suspicious request not challenged", w.Code, event.bot)
	}
	pending := cookieNamed(t, w, botPendingCookie)
	if !pending.Secure || !pending.HttpOnly || pending.SameSite != http.SameSiteStrictMode || pending.Domain != "" {
		t.Fatal("unsafe pending cookie")
	}
	claims, answer := captchaAnswer(t, a, pending)
	for _, media := range []string{"image", "audio"} {
		w, _ = botProbe(t, b, "GET", botChallengePrefix+"/"+media, "HeadlessChrome/144", "", pending)
		if w.Code != 200 || w.Body.Len() < 100 {
			t.Fatal("cross-replica media unavailable", media, w.Code)
		}
	}
	csrf := a.botMAC("csrf", claims.ID+":"+claims.Binding)
	w, event = botProbe(t, b, "POST", botChallengePrefix+"/verify", "HeadlessChrome/144", url.Values{"csrf": {csrf}, "answer": {answer}}.Encode(), pending)
	if w.Code != 303 || w.Header().Get("Location") != "/products?q=chair" || event.bot.Decision != "passed" {
		t.Fatalf("verification failed: %d %s %+v", w.Code, w.Body.String(), event.bot)
	}
	clearance := cookieNamed(t, w, botClearanceCookie)
	for _, app := range []*App{a, b} {
		w, event = botProbe(t, app, "GET", "/products", "HeadlessChrome/144", "", clearance)
		if w.Code != 200 || event.bot.Decision != "cleared" {
			t.Fatal("clearance not shared", w.Code, event.bot)
		}
	}
	w, _ = botProbe(t, a, "POST", botChallengePrefix+"/verify", "HeadlessChrome/144", url.Values{"csrf": {csrf}, "answer": {answer}}.Encode(), pending)
	if w.Code != 400 {
		t.Fatal("one-time challenge replay accepted", w.Code)
	}
	w, _ = botProbe(t, a, "GET", "/", "different headlesschrome", "", clearance)
	if w.Code != 403 {
		t.Fatal("clearance reused with another client")
	}
	// A cleared client still consumes the independent flood budget.
	p := a.active.Load().protection[site].ProtectionSettings
	p.Mode = "block"
	p.RequestsPerSecond = 1
	p.Burst = 1
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	// Settings changes invalidate old clearance, so issue/solve a new proof directly in the test.
	r := httptest.NewRequest("GET", "https://bot.test/", nil)
	r.Header.Set("User-Agent", "HeadlessChrome/144")
	policy := a.active.Load().protection[site]
	br := a.botContext(policy, site, 0, 0, r, netip.MustParseAddr("198.51.100.5"), true)
	next, e := a.issueBotChallenge(context.Background(), br, "/")
	if e != nil {
		t.Fatal(e)
	}
	var cipher []byte
	a.db.QueryRow(context.Background(), "SELECT answer_cipher FROM bot_challenges WHERE id=$1", next.ID).Scan(&cipher)
	digits, _ := open(a.cfg.Key, a.cfg.KeyID+":bot-answer:"+next.ID+":"+br.scope, cipher)
	for i := range digits {
		digits[i] += '0'
	}
	proof, e := a.solveBotChallenge(context.Background(), br, next, string(digits), 30)
	if e != nil {
		t.Fatal(e)
	}
	rec := httptest.NewRecorder()
	a.setBotCookie(rec, botClearanceCookie, proof, 1800)
	fresh := cookieNamed(t, rec, botClearanceCookie)
	w, _ = botProbe(t, a, "GET", "/", "HeadlessChrome/144", "", fresh)
	if w.Code != 200 {
		t.Fatal("fresh clearance failed", w.Code)
	}
	w, _ = botProbe(t, a, "GET", "/", "HeadlessChrome/144", "", fresh)
	if w.Code != 429 {
		t.Fatal("clearance bypassed flood protection", w.Code)
	}
}

func TestCaptchaAttemptsOriginReplayAndExpiry(t *testing.T) {
	a, b, _, _, _ := captchaFixture(t)
	w, _ := botProbe(t, a, "GET", "/", "headlesschrome", "")
	pending := cookieNamed(t, w, botPendingCookie)
	claims, answer := captchaAnswer(t, a, pending)
	wrong := "000000"
	if answer == wrong {
		wrong = "111111"
	}
	csrf := a.botMAC("csrf", claims.ID+":"+claims.Binding)
	for range 5 {
		w, _ = botProbe(t, b, "POST", botChallengePrefix+"/verify", "headlesschrome", url.Values{"csrf": {csrf}, "answer": {wrong}}.Encode(), pending)
		if w.Code != 400 {
			t.Fatal("unexpected guess status", w.Code)
		}
	}
	w, _ = botProbe(t, a, "POST", botChallengePrefix+"/verify", "headlesschrome", url.Values{"csrf": {csrf}, "answer": {answer}}.Encode(), pending)
	if w.Code != 400 {
		t.Fatal("exhausted challenge accepted")
	}
	w, _ = botProbe(t, a, "GET", "/", "headlesschrome", "")
	pending = cookieNamed(t, w, botPendingCookie)
	claims, answer = captchaAnswer(t, a, pending)
	csrf = a.botMAC("csrf", claims.ID+":"+claims.Binding)
	// Only one simultaneous replica can redeem the solution.
	var successes atomic.Int64
	var wg sync.WaitGroup
	for _, app := range []*App{a, b} {
		wg.Add(1)
		go func(app *App) {
			defer wg.Done()
			proof, e := app.solveBotChallenge(context.Background(), botRequest{scope: claims.Scope, binding: claims.Binding}, claims, answer, 30)
			if e == nil && proof.ID != "" {
				successes.Add(1)
			}
		}(app)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("challenge redeemed multiple times", successes.Load())
	}
	for _, value := range []string{"//evil.example/", "/\\evil.example/", "https://evil.example/", "/%2f%2fevil.example/"} {
		if safeBotReturn(value) != "/" {
			t.Fatal("open redirect accepted", value)
		}
	}
}

func TestCaptchaCSRFAndSignatureIsolation(t *testing.T) {
	a, _, _, site, _ := captchaFixture(t)
	w, _ := botProbe(t, a, "GET", "/", "headlesschrome", "")
	pending := cookieNamed(t, w, botPendingCookie)
	claims, answer := captchaAnswer(t, a, pending)
	form := url.Values{"csrf": {a.botMAC("csrf", claims.ID+":"+claims.Binding)}, "answer": {answer}}.Encode()
	r := httptest.NewRequest("POST", "https://bot.test"+botChallengePrefix+"/verify", strings.NewReader(form))
	r.TLS = &tls.ConnectionState{ServerName: "bot.test"}
	r.RemoteAddr = "198.51.100.5:3000"
	r.Header.Set("User-Agent", "headlesschrome")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.test")
	r.AddCookie(pending)
	rec := httptest.NewRecorder()
	a.Public(rec, r)
	<-a.access
	if rec.Code != 403 {
		t.Fatal("cross-origin answer accepted")
	}
	w, _ = botProbe(t, a, "POST", botChallengePrefix+"/verify", "headlesschrome", url.Values{"csrf": {"forged"}, "answer": {answer}}.Encode(), pending)
	if w.Code != 403 {
		t.Fatal("forged CSRF accepted")
	}
	var attempts int
	a.db.QueryRow(context.Background(), "SELECT attempts FROM bot_challenges WHERE id=$1", claims.ID).Scan(&attempts)
	if attempts != 0 {
		t.Fatal("CSRF rejection changed challenge state")
	}
	w, _ = botProbe(t, a, "POST", botChallengePrefix+"/verify", "headlesschrome", form, pending)
	clearance := cookieNamed(t, w, botClearanceCookie)
	set, _ := bundledSignatureSet()
	managed, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block"})
	if e != nil {
		t.Fatal(e)
	}
	policy := a.active.Load().protection[site]
	a.active.Load().policyBindings = map[int64][]compiledPolicyBinding{site: {{Protection: policy, Managed: managed}}}
	w, event := botProbe(t, a, "GET", "/?q="+url.QueryEscape("1' UNION SELECT password FROM users --"), "headlesschrome", "", clearance)
	if w.Code != 403 || event.bot.Decision != "cleared" || len(event.managed.RuleIDs) == 0 {
		t.Fatalf("clearance bypassed signatures: %d %+v", w.Code, event)
	}
	// Expired proof is rejected before any cache hit can grant access.
	encoded, _ := base64.RawURLEncoding.DecodeString(clearance.Value)
	raw, _ := open(a.cfg.Key, a.cfg.KeyID+":bot-cookie-v1", encoded)
	var proof botClaims
	json.Unmarshal(raw, &proof)
	proof.Expires = time.Now().Add(-time.Second).Unix()
	clearance.Value, _ = a.encodeBotCookie(proof)
	context := a.botContext(policy, site, 0, 0, r, netip.MustParseAddr("198.51.100.5"), true)
	if _, ok := a.readBotCookie(func() *http.Request {
		q := httptest.NewRequest("GET", "https://bot.test/", nil)
		q.AddCookie(clearance)
		return q
	}(), botClearanceCookie, "clearance", context); ok {
		t.Fatal("expired clearance accepted")
	}
}

func TestCaptchaOwnedHeadersCannotBeOverridden(t *testing.T) {
	a, _, _, site, _ := captchaFixture(t)
	settings, _ := normalizeHeaders(HeaderSettings{ResponseSet: map[string]string{"Content-Type": "application/json", "Cache-Control": "public,max-age=99999", "Content-Security-Policy": "default-src 'none'"}, ResponseRemove: []string{"Set-Cookie"}, HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 86400}})
	for _, route := range a.active.Load().routes {
		if route.site.ID == site {
			route.site.Headers = &settings
		}
	}
	w, _ := botProbe(t, a, "GET", "/", "headlesschrome", "")
	if w.Code != 403 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "nonce-") || w.Header().Get("Strict-Transport-Security") != "max-age=86400" {
		t.Fatal("application headers broke owned challenge", w.Header())
	}
	cookieNamed(t, w, botPendingCookie)
}
