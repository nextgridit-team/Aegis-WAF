package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dchest/captcha"
	"github.com/jackc/pgx/v5"
)

const botChallengePrefix = "/.aegis/challenge"
const botPendingCookie = "__Host-aegis_challenge"
const botClearanceCookie = "__Host-aegis_clearance"

type botClaims struct {
	Kind     string `json:"k"`
	ID       string `json:"i"`
	Scope    string `json:"s"`
	Binding  string `json:"b"`
	ReturnTo string `json:"r,omitempty"`
	Expires  int64  `json:"e"`
	Score    int    `json:"n,omitempty"`
}
type botClearanceCache struct {
	sync.Mutex
	values map[string]int64
}

func (c *botClearanceCache) contains(key string, now int64) bool {
	c.Lock()
	defer c.Unlock()
	return c.values[key] > now
}
func (c *botClearanceCache) remember(key string, expires int64) {
	c.Lock()
	defer c.Unlock()
	if c.values == nil {
		c.values = map[string]int64{}
	}
	if len(c.values) >= 10000 {
		now := time.Now().Unix()
		for k, e := range c.values {
			if e <= now {
				delete(c.values, k)
			}
		}
	}
	if len(c.values) < 10000 {
		c.values[key] = expires
	}
}
func (a *App) botMAC(purpose, value string) string {
	h := hmac.New(sha256.New, a.cfg.Key)
	io.WriteString(h, "aegis-bot-v1:"+purpose+":")
	io.WriteString(h, value)
	return hex.EncodeToString(h.Sum(nil))
}
func (a *App) encodeBotCookie(c botClaims) (string, error) {
	raw, e := json.Marshal(c)
	if e != nil {
		return "", e
	}
	encrypted, e := seal(a.cfg.Key, a.cfg.KeyID+":bot-cookie-v1", raw)
	return base64.RawURLEncoding.EncodeToString(encrypted), e
}
func (a *App) readBotCookie(r *http.Request, name, kind string, b botRequest) (botClaims, bool) {
	var claims botClaims
	cookie, e := r.Cookie(name)
	if e != nil || len(cookie.Value) > 4096 {
		return claims, false
	}
	raw, e := base64.RawURLEncoding.DecodeString(cookie.Value)
	if e != nil {
		return claims, false
	}
	raw, e = open(a.cfg.Key, a.cfg.KeyID+":bot-cookie-v1", raw)
	if e != nil || json.Unmarshal(raw, &claims) != nil {
		return claims, false
	}
	now := time.Now().Unix()
	valid := claims.Kind == kind && claims.Expires > now && claims.Expires <= now+121*60 && len(claims.ID) == 43 && claims.Scope == b.scope && claims.Binding == b.binding && b.secure
	return claims, valid
}
func (a *App) setBotCookie(w http.ResponseWriter, name string, claims botClaims, maxAge int) error {
	value, e := a.encodeBotCookie(claims)
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
	return nil
}
func clearBotPending(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: botPendingCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func (a *App) hasBotClearance(ctx context.Context, r *http.Request, b botRequest) (bool, error) {
	claims, ok := a.readBotCookie(r, botClearanceCookie, "clearance", b)
	if !ok {
		return false, nil
	}
	key := hash(claims.ID)
	if a.botClearances.contains(key, time.Now().Unix()) {
		return true, nil
	}
	var exists bool
	e := a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM bot_clearances WHERE token_hash=$1 AND scope=$2 AND binding=$3 AND expires_at>now())", key, b.scope, b.binding).Scan(&exists)
	if e != nil {
		return false, e
	}
	if exists {
		a.botClearances.remember(key, claims.Expires)
	}
	return exists, nil
}
func botReturnPath(r *http.Request) string {
	if r.Method != "GET" && r.Method != "HEAD" {
		return "/"
	}
	return safeBotReturn(r.URL.RequestURI())
}
func safeBotReturn(value string) string {
	parsed, e := url.ParseRequestURI(value)
	decoded, _ := url.PathUnescape(value)
	if e != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(decoded, "//") || strings.ContainsAny(decoded, "\\\r\n") || strings.HasPrefix(parsed.Path, botChallengePrefix) || len(value) > 2048 {
		return "/"
	}
	return value
}
func (a *App) issueBotChallenge(ctx context.Context, b botRequest, returnTo string) (botClaims, error) {
	claims := botClaims{Kind: "challenge", ID: token(), Scope: b.scope, Binding: b.binding, ReturnTo: safeBotReturn(returnTo), Expires: time.Now().Add(5 * time.Minute).Unix(), Score: b.result.Score}
	digits := captcha.RandomDigits(6)
	encrypted, e := seal(a.cfg.Key, a.cfg.KeyID+":bot-answer:"+claims.ID+":"+b.scope, digits)
	if e != nil {
		return claims, e
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return claims, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(700016)"); e != nil {
		return claims, e
	}
	var total, recent int
	if e = tx.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE client_bucket=$1 AND created_at>now()-interval '1 minute') FROM bot_challenges", b.bucket).Scan(&total, &recent); e != nil {
		return claims, e
	}
	if total >= 10000 || recent >= 10 {
		return claims, apiError{429, "verification temporarily rate limited; try again later"}
	}
	_, e = tx.Exec(ctx, "INSERT INTO bot_challenges(id,scope,binding,client_bucket,answer_cipher,key_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)", claims.ID, b.scope, b.binding, b.bucket, encrypted, a.cfg.KeyID, time.Unix(claims.Expires, 0))
	if e != nil {
		return claims, e
	}
	return claims, tx.Commit(ctx)
}
func (a *App) pendingBotChallenge(ctx context.Context, r *http.Request, b botRequest) (botClaims, bool, error) {
	claims, ok := a.readBotCookie(r, botPendingCookie, "challenge", b)
	if !ok {
		return claims, false, nil
	}
	var exists bool
	e := a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM bot_challenges WHERE id=$1 AND scope=$2 AND binding=$3 AND NOT used AND attempts<5 AND expires_at>now())", claims.ID, b.scope, b.binding).Scan(&exists)
	return claims, exists, e
}
func (a *App) renderBotChallenge(w http.ResponseWriter, r *http.Request, b botRequest, claims botClaims, message string, status int) {
	nonce := token()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'nonce-"+nonce+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Aegis-Challenge", "required")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = botChallengePage.Execute(w, map[string]string{"Nonce": nonce, "CSRF": a.botMAC("csrf", claims.ID+":"+b.binding), "Message": message, "Prefix": botChallengePrefix})
}
func (a *App) requireBotChallenge(w http.ResponseWriter, r *http.Request, b botRequest, reliable bool) {
	if !b.secure || !reliable {
		http.Error(w, "verification requires HTTPS and reliable client identity", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	claims, exists, e := a.pendingBotChallenge(ctx, r, b)
	if e == nil && !exists {
		claims, e = a.issueBotChallenge(ctx, b, botReturnPath(r))
	}
	if e != nil {
		botChallengeFailure(w, e)
		return
	}
	if e = a.setBotCookie(w, botPendingCookie, claims, 300); e != nil {
		botChallengeFailure(w, e)
		return
	}
	if r.Method == "GET" && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		a.renderBotChallenge(w, r, b, claims, "Complete this verification to continue.", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Aegis-Challenge", "required")
	respond(w, 403, map[string]any{"error": "bot_verification_required", "challenge_url": botChallengePrefix, "retry_original_request": true, "message": "Complete verification in a browser, then retry. This request was not forwarded."})
}
func botChallengeFailure(w http.ResponseWriter, e error) {
	var api apiError
	if errors.As(e, &api) {
		if api.status == 429 {
			w.Header().Set("Retry-After", "60")
		}
		http.Error(w, api.message, api.status)
		return
	}
	http.Error(w, "verification temporarily unavailable", 503)
}
func (a *App) serveBotEndpoint(w http.ResponseWriter, r *http.Request, b botRequest, p *protectionPolicy, reliable bool) botResult {
	result := botResult{Threshold: p.BotChallenge.Threshold, Decision: "failed"}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !p.BotChallenge.Enabled || p.BotMode == "off" {
		http.NotFound(w, r)
		return result
	}
	if !b.secure || !reliable {
		http.Error(w, "verification requires HTTPS and reliable client identity", 503)
		return result
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	claims, ok, e := a.pendingBotChallenge(ctx, r, b)
	if e != nil {
		botChallengeFailure(w, e)
		return result
	}
	if !ok {
		http.Error(w, "verification expired or unavailable; return to the application to try again", 400)
		return result
	}
	result.Score = claims.Score
	switch r.URL.Path {
	case botChallengePrefix:
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", 405)
			return result
		}
		result.Decision = "challenge"
		a.renderBotChallenge(w, r, b, claims, "Complete this verification to continue.", 200)
	case botChallengePrefix + "/image", botChallengePrefix + "/audio":
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", 405)
			return result
		}
		a.botMedia(w, r, ctx, b, claims)
		result.Decision = "challenge"
	case botChallengePrefix + "/verify":
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", 405)
			return result
		}
		if r.Header.Get("Origin") != "https://"+r.Host {
			http.Error(w, "verification origin rejected", 403)
			return result
		}
		if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/x-www-form-urlencoded" {
			http.Error(w, "invalid verification form", 415)
			return result
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if e = r.ParseForm(); e != nil {
			http.Error(w, "invalid verification form", 400)
			return result
		}
		csrf := a.botMAC("csrf", claims.ID+":"+b.binding)
		if len(r.PostForm["csrf"]) != 1 || subtle.ConstantTimeCompare([]byte(csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
			http.Error(w, "verification token rejected", 403)
			return result
		}
		if r.PostForm.Get("refresh") == "1" {
			_, e = a.db.Exec(ctx, "UPDATE bot_challenges SET used=true WHERE id=$1 AND scope=$2 AND binding=$3", claims.ID, b.scope, b.binding)
			if e == nil {
				claims, e = a.issueBotChallenge(ctx, b, claims.ReturnTo)
			}
			if e != nil {
				botChallengeFailure(w, e)
				return result
			}
			if e = a.setBotCookie(w, botPendingCookie, claims, 300); e != nil {
				botChallengeFailure(w, e)
				return result
			}
			result.Decision = "challenge"
			a.renderBotChallenge(w, r, b, claims, "Try this new verification.", 200)
			return result
		}
		answer := r.PostForm.Get("answer")
		if len(r.PostForm["answer"]) != 1 || len(answer) != 6 || strings.IndexFunc(answer, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			http.Error(w, "enter the six digits shown or spoken", 400)
			return result
		}
		clearance, e := a.solveBotChallenge(ctx, b, claims, answer, p.BotChallenge.ClearanceMinutes)
		if e != nil {
			botChallengeFailure(w, e)
			return result
		}
		if clearance.ID == "" {
			a.renderBotChallenge(w, r, b, claims, "The answer was incorrect. Try again or request a new challenge.", 400)
			return result
		}
		if e = a.setBotCookie(w, botClearanceCookie, clearance, p.BotChallenge.ClearanceMinutes*60); e != nil {
			botChallengeFailure(w, e)
			return result
		}
		clearBotPending(w)
		result.Decision = "passed"
		http.Redirect(w, r, safeBotReturn(claims.ReturnTo), 303)
	default:
		http.NotFound(w, r)
	}
	return result
}
func (a *App) botMedia(w http.ResponseWriter, r *http.Request, ctx context.Context, b botRequest, claims botClaims) {
	select {
	case a.botWork <- struct{}{}:
		defer func() { <-a.botWork }()
	default:
		http.Error(w, "verification busy; retry shortly", 503)
		return
	}
	var encrypted []byte
	var keyID string
	e := a.db.QueryRow(ctx, "UPDATE bot_challenges SET media_reads=media_reads+1 WHERE id=$1 AND scope=$2 AND binding=$3 AND NOT used AND expires_at>now() AND media_reads<20 RETURNING answer_cipher,key_id", claims.ID, b.scope, b.binding).Scan(&encrypted, &keyID)
	if errors.Is(e, pgx.ErrNoRows) {
		http.Error(w, "verification expired or temporarily rate limited", 429)
		return
	}
	if e != nil {
		botChallengeFailure(w, e)
		return
	}
	if keyID != a.cfg.KeyID {
		botChallengeFailure(w, errors.New("key unavailable"))
		return
	}
	digits, e := open(a.cfg.Key, keyID+":bot-answer:"+claims.ID+":"+b.scope, encrypted)
	if e != nil || len(digits) != 6 {
		botChallengeFailure(w, errors.New("answer unavailable"))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/audio") {
		w.Header().Set("Content-Type", "audio/wav")
		_, _ = captcha.NewAudio(claims.ID, digits, "en").WriteTo(w)
	} else {
		w.Header().Set("Content-Type", "image/png")
		_, _ = captcha.NewImage(claims.ID, digits, 240, 80).WriteTo(w)
	}
}
func (a *App) solveBotChallenge(ctx context.Context, b botRequest, claims botClaims, answer string, minutes int) (botClaims, error) {
	var empty botClaims
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback(ctx)
	var encrypted []byte
	var keyID string
	e = tx.QueryRow(ctx, "SELECT answer_cipher,key_id FROM bot_challenges WHERE id=$1 AND scope=$2 AND binding=$3 AND NOT used AND attempts<5 AND expires_at>now() FOR UPDATE", claims.ID, b.scope, b.binding).Scan(&encrypted, &keyID)
	if errors.Is(e, pgx.ErrNoRows) {
		return empty, apiError{400, "verification expired or exhausted; return to the application"}
	}
	if e != nil {
		return empty, e
	}
	if keyID != a.cfg.KeyID {
		return empty, errors.New("key unavailable")
	}
	digits, e := open(a.cfg.Key, keyID+":bot-answer:"+claims.ID+":"+b.scope, encrypted)
	if e != nil || len(digits) != 6 {
		return empty, errors.New("answer unavailable")
	}
	expected := make([]byte, 6)
	for i, d := range digits {
		expected[i] = '0' + d
	}
	if subtle.ConstantTimeCompare(expected, []byte(answer)) != 1 {
		_, e = tx.Exec(ctx, "UPDATE bot_challenges SET attempts=attempts+1,used=(attempts+1>=5) WHERE id=$1", claims.ID)
		if e != nil {
			return empty, e
		}
		return empty, tx.Commit(ctx)
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(700017)"); e != nil {
		return empty, e
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM bot_clearances").Scan(&count); e != nil {
		return empty, e
	}
	if count >= 100000 {
		return empty, apiError{503, "verification capacity unavailable"}
	}
	clearance := botClaims{Kind: "clearance", ID: token(), Scope: b.scope, Binding: b.binding, Expires: time.Now().Add(time.Duration(minutes) * time.Minute).Unix()}
	if _, e = tx.Exec(ctx, "UPDATE bot_challenges SET used=true WHERE id=$1", claims.ID); e != nil {
		return empty, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO bot_clearances(token_hash,scope,binding,expires_at) VALUES($1,$2,$3,$4)", hash(clearance.ID), b.scope, b.binding, time.Unix(clearance.Expires, 0)); e != nil {
		return empty, e
	}
	if e = tx.Commit(ctx); e != nil {
		return empty, e
	}
	a.botClearances.remember(hash(clearance.ID), clearance.Expires)
	return clearance, nil
}
func (a *App) BotChallengeWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.initialized.Load() {
				continue
			}
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, e := a.db.Exec(c, "DELETE FROM bot_challenges WHERE id IN (SELECT id FROM bot_challenges WHERE expires_at<=now() LIMIT 10000)")
			if e == nil {
				_, e = a.db.Exec(c, "DELETE FROM bot_clearances WHERE token_hash IN (SELECT token_hash FROM bot_clearances WHERE expires_at<=now() LIMIT 10000)")
			}
			cancel()
			if e != nil {
				slog.Warn("bot verification expiry cleanup unavailable")
			}
		}
	}
}

var botChallengePage = template.Must(template.New("bot-challenge").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verify your request · Aegis WAF</title><style nonce="{{.Nonce}}">*{box-sizing:border-box}body{margin:0;background:#10181e;color:#e4edf1;font:16px/1.6 system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}main{max-width:460px;width:100%;padding:32px;border:1px solid #30414b;border-radius:16px;background:#18232b}h1{font-size:25px;margin-top:0}.muted{color:#a3b4be}label{display:block;margin:16px 0 8px}input,button{font:inherit;border-radius:8px;padding:12px;width:100%}input{background:#10181e;color:#fff;border:1px solid #58716d}button{margin-top:16px;background:#78d8bc;color:#10211e;border:0;cursor:pointer;font-weight:650}.secondary{background:transparent;color:#a3b4be;border:1px solid #30414b}img,audio{max-width:100%;display:block;margin:16px auto}small{display:block;margin-top:24px;overflow-wrap:anywhere}a{color:#78d8bc}</style></head><body><main><h1>Verify your request</h1><p role="status">{{.Message}}</p><p class="muted">This request needs a quick check before reaching the application.</p><img src="{{.Prefix}}/image" width="240" height="80" alt="Six-digit verification image. An audio alternative is available below."><audio controls preload="none" aria-label="Listen to the six verification digits"><source src="{{.Prefix}}/audio" type="audio/wav"></audio><form action="{{.Prefix}}/verify" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="answer">Enter the six digits</label><input id="answer" name="answer" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required autocomplete="off"><button type="submit">Verify and continue</button><button class="secondary" type="submit" name="refresh" value="1" formnovalidate>Get a new challenge</button></form><small class="muted">Self-hosted verification by Aegis WAF. No external CAPTCHA service is contacted. Verification does not exempt requests from other security checks.</small></main></body></html>`))

// Gateway clearance is not an application credential. Keep it out of upstream
// logs/application code while preserving unrelated application cookies.
func stripBotCookies(r *http.Request) {
	if !strings.Contains(strings.Join(r.Header.Values("Cookie"), ";"), "__Host-aegis_") {
		return
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != botPendingCookie && cookie.Name != botClearanceCookie {
			r.AddCookie(cookie)
		}
	}
}
