package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type applicationAccessSnapshot struct {
	applicationAccess
	ProviderType    string
	ProviderEnabled bool
}

type applicationClientIPKey struct{}

func loadApplicationAccess(ctx context.Context, tx pgx.Tx, s *snapshot) error {
	s.applicationAccess = map[int64]applicationAccessSnapshot{}
	rows, e := tx.Query(ctx, "SELECT a.site_id,a.revision,a.settings,coalesce(p.settings->>'type',''),coalesce((p.settings->>'enabled')::bool,false) FROM application_access a LEFT JOIN identity_providers p ON p.id=a.provider_id")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var value applicationAccessSnapshot
		var raw []byte
		if e = rows.Scan(&value.SiteID, &value.Revision, &raw, &value.ProviderType, &value.ProviderEnabled); e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &value.Settings); e != nil {
			return e
		}
		if value.Settings, e = normalizeApplicationAccess(value.Settings); e != nil {
			return e
		}
		s.applicationAccess[value.SiteID] = value
	}
	if e = rows.Err(); e != nil {
		return e
	}
	for _, r := range s.routes {
		r.site.AccessRequired = s.applicationAccess[r.site.ID].Settings.Enabled
	}
	return nil
}

func safeApplicationReturn(raw string) string {
	if len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\x00") {
		return "/"
	}
	u, e := url.ParseRequestURI(raw)
	if e != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(u.Path, applicationAuthPrefix) || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\\r\n\x00") {
		return "/"
	}
	return raw
}
func stripApplicationCredentials(r *http.Request) {
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-aegis-identity-") {
			r.Header.Del(key)
		}
	}
	cookies := r.Cookies()
	owned := false
	for _, cookie := range cookies {
		if cookie.Name == applicationSessionCookie || cookie.Name == applicationFlowCookie {
			owned = true
			break
		}
	}
	if !owned {
		return
	}
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != applicationSessionCookie && cookie.Name != applicationFlowCookie {
			r.AddCookie(cookie)
		}
	}
}
func applicationCookie(w http.ResponseWriter, name, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}
func applicationAuthHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

var applicationLoginTemplate = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · Aegis</title><style>body{font:16px system-ui;background:#101827;color:#edf2fa;display:grid;place-items:center;min-height:90vh;margin:0;padding:1rem}main{width:min(100%,26rem)}label{display:block;margin:1rem 0}input,button{box-sizing:border-box;width:100%;padding:.8rem;border-radius:.5rem;border:1px solid #607086;font:inherit}button{background:#d8edff;color:#152437;cursor:pointer}p{line-height:1.5;color:#becbdd}h1{font-size:1.8rem}a{color:#a9d5ff}</style></head><body><main><p>Aegis · Application access</p><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .Action}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="return" value="{{.Return}}">{{if .Login}}<label>Username<input name="username" required maxlength="256" autocomplete="username" autofocus></label><label>Password<input name="password" type="password" required maxlength="4096" autocomplete="current-password"></label>{{end}}<button type="submit">{{.Button}}</button></form>{{end}}</main></body></html>`))

func applicationPage(w http.ResponseWriter, status int, title, message, action, csrf, returnTo, button string, login bool) {
	applicationAuthHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = applicationLoginTemplate.Execute(w, map[string]any{"Title": title, "Message": message, "Action": action, "CSRF": csrf, "Return": returnTo, "Button": button, "Login": login})
}
func (a *App) logApplicationAuthRequest(r *http.Request, site Site, start time.Time, status int) {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	event := accessEvent{at: time.Now(), host: requestHost(r.Host), site: site.ID, siteName: site.Name, method: r.Method, status: status, duration: time.Since(start).Milliseconds(), peer: peer, responseSource: "application_auth", blocked: status >= 400}
	if status >= 400 {
		event.signals = []string{"application_auth"}
	}
	select {
	case a.access <- event:
	default:
		a.dropped.Add(1)
		a.stdoutDropped.Add(1)
	}
}
func (a *App) applicationAuthAudit(ctx context.Context, site, provider int64, action string, subject string) error {
	actor := "application-anonymous"
	if subject != "" {
		actor = "application-user:" + strconv.FormatInt(provider, 10) + ":" + hash(subject)
	}
	_, e := a.db.Exec(ctx, "INSERT INTO audit_events(actor,action,resource) VALUES($1,$2,$3)", actor, action, strconv.FormatInt(site, 10))
	return e
}
func (a *App) applicationLoginLimit(r *http.Request, provider int64, username string) error {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if verified, ok := r.Context().Value(applicationClientIPKey{}).(string); ok {
		peer = verified
	}
	if e := a.throttle(r.Context(), "application-auth-peer:"+hash(peer), 30, 5*time.Minute); e != nil {
		return e
	}
	if username != "" {
		return a.throttle(r.Context(), "application-auth-user:"+hash(fmt.Sprint(provider)+":"+strings.ToLower(username)), 15, 5*time.Minute)
	}
	return nil
}
func (a *App) createApplicationSession(ctx context.Context, access applicationAccess, p storedIdentityProvider, identity applicationIdentity, expiry time.Time) (string, error) {
	if !boundedApplicationIdentity(identity) || !identityAllowed(access.Settings, identity, p.Settings.Type) {
		return "", apiError{403, "identity does not belong to an allowed group"}
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(700040)"); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, "DELETE FROM application_sessions WHERE expires_at<=now()"); e != nil {
		return "", e
	}
	var available bool
	if e = tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM application_sessions)<10000 AND EXISTS(SELECT 1 FROM application_access a JOIN identity_providers p ON p.id=a.provider_id WHERE a.site_id=$1 AND a.revision=$2 AND p.id=$3 AND p.revision=$4 AND (a.settings->>'enabled')::bool AND (p.settings->>'enabled')::bool)", access.SiteID, access.Revision, p.ID, p.Revision).Scan(&available); e != nil {
		return "", e
	}
	if !available {
		return "", apiError{409, "authentication configuration changed or session capacity reached; sign in again"}
	}
	until := time.Now().Add(time.Duration(access.Settings.SessionMinutes) * time.Minute)
	if !expiry.IsZero() && expiry.Before(until) {
		until = expiry
	}
	if !until.After(time.Now()) {
		return "", apiError{401, "identity token expired"}
	}
	session := token()
	raw, _ := json.Marshal(identity)
	if _, e = tx.Exec(ctx, "INSERT INTO application_sessions(id,token_hash,site_id,provider_id,access_revision,provider_revision,identity,origin,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", token(), hash(session), access.SiteID, p.ID, access.Revision, p.Revision, raw, access.Settings.PublicOrigin, until); e != nil {
		return "", e
	}
	if e = audit(ctx, tx, "application-user:"+strconv.FormatInt(p.ID, 10)+":"+hash(identity.Subject), "application_auth.succeeded", strconv.FormatInt(access.SiteID, 10)); e != nil {
		return "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", e
	}
	return session, nil
}
func (a *App) validApplicationSession(ctx context.Context, r *http.Request, access applicationAccess, p storedIdentityProvider) (bool, error) {
	cookie, e := r.Cookie(applicationSessionCookie)
	if e != nil || len(cookie.Value) > 128 {
		return false, nil
	}
	var raw []byte
	e = a.db.QueryRow(ctx, `SELECT s.identity FROM application_sessions s JOIN application_access a ON a.site_id=s.site_id JOIN identity_providers p ON p.id=s.provider_id WHERE s.token_hash=$1 AND s.site_id=$2 AND s.provider_id=$3 AND s.origin=$4 AND s.expires_at>now() AND s.access_revision=a.revision AND s.provider_revision=p.revision AND a.revision=$5 AND p.revision=$6 AND (a.settings->>'enabled')::bool AND (p.settings->>'enabled')::bool`, hash(cookie.Value), access.SiteID, p.ID, access.Settings.PublicOrigin, access.Revision, p.Revision).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var identity applicationIdentity
	if e = json.Unmarshal(raw, &identity); e != nil {
		return false, e
	}
	return identityAllowed(access.Settings, identity, p.Settings.Type), nil
}

// Runs before request-body inspection: authentication credentials and callback
// codes can never reach traffic capture, native rules or the upstream proxy.
func (a *App) applicationAccessGate(w http.ResponseWriter, r *http.Request, site Site, secure bool) bool {
	if !site.AccessRequired && !strings.HasPrefix(r.URL.Path, applicationAuthPrefix) {
		return false
	}
	start := time.Now()
	rec := &statusWriter{ResponseWriter: w, status: 200, beforeHeader: func(h http.Header) {
		applicationAuthHeaders(w)
		// Retain configured HSTS without letting application rewrites replace
		// login cookies, form policy or no-store headers.
		security := http.Header{}
		site.Headers.applyResponseSecurity(security, secure)
		if value := security.Get("Strict-Transport-Security"); value != "" {
			h.Set("Strict-Transport-Security", value)
		}
	}}
	handled := true
	defer func() {
		if handled {
			a.logApplicationAuthRequest(r, site, start, rec.status)
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	access, e := readApplicationAccess(ctx, a.db, site.ID)
	if e != nil {
		http.Error(rec, "application authentication unavailable", 503)
		return true
	}
	if !access.Settings.Enabled {
		if strings.HasPrefix(r.URL.Path, applicationAuthPrefix) {
			http.NotFound(rec, r)
			return true
		}
		handled = false
		return false
	}
	if r.URL.Path == applicationAuthPrefix+"callback" {
		expected, err := url.Parse(access.Settings.PublicOrigin)
		if err != nil || !secure || r.Host != expected.Host || r.URL.EscapedPath() != applicationAuthPrefix+"callback" {
			http.Error(rec, "callback URL must exactly match the configured HTTPS application origin", http.StatusBadRequest)
			return true
		}
	}
	if !secure {
		if r.Method == "GET" || r.Method == "HEAD" {
			http.Redirect(rec, r, access.Settings.PublicOrigin+safeApplicationReturn(r.URL.RequestURI()), http.StatusPermanentRedirect)
		} else {
			http.Error(rec, "HTTPS is required for application authentication", http.StatusUpgradeRequired)
		}
		return true
	}
	expected, _ := url.Parse(access.Settings.PublicOrigin)
	if !strings.EqualFold(r.Host, expected.Host) {
		http.Redirect(rec, r, access.Settings.PublicOrigin+safeApplicationReturn(r.URL.RequestURI()), http.StatusPermanentRedirect)
		return true
	}
	provider, e := readIdentityProvider(ctx, a.db, access.Settings.ProviderID)
	if e != nil || !provider.Settings.Enabled {
		http.Error(rec, "application identity provider unavailable", 503)
		return true
	}
	switch r.URL.Path {
	case applicationAuthPrefix + "login":
		if provider.Settings.Type == "oidc" {
			if r.Method != "GET" {
				http.Error(rec, "method not allowed", 405)
				return true
			}
			e = a.startOIDC(rec, r, access, provider)
		} else {
			e = a.serveLDAPLogin(rec, r, access, provider)
		}
	case applicationAuthPrefix + "callback":
		if r.Method != "GET" || provider.Settings.Type != "oidc" {
			http.Error(rec, "method not allowed", 405)
			return true
		}
		e = a.finishOIDC(rec, r, access, provider)
	case applicationAuthPrefix + "logout":
		e = a.serveApplicationLogout(rec, r, access)
	default:
		if strings.HasPrefix(r.URL.Path, applicationAuthPrefix) {
			http.NotFound(rec, r)
			return true
		}
		var valid bool
		valid, e = a.validApplicationSession(ctx, r, access, provider)
		if e == nil && valid {
			handled = false
			return false
		}
		if e == nil {
			applicationCookie(rec, applicationSessionCookie, "", -1)
			if !site.machineEndpoint() && (r.Method == "GET" || r.Method == "HEAD") && !strings.Contains(r.Header.Get("Accept"), "application/json") {
				http.Redirect(rec, r, applicationAuthPrefix+"login?return="+url.QueryEscape(safeApplicationReturn(r.URL.RequestURI())), http.StatusFound)
			} else {
				respond(rec, 401, map[string]string{"error": "authentication_required", "login_url": access.Settings.PublicOrigin + applicationAuthPrefix + "login"})
			}
			return true
		}
	}
	if e != nil {
		status, message := 503, "application authentication unavailable; retry shortly"
		var api apiError
		if errors.As(e, &api) {
			status, message = api.status, api.message
		}
		_ = a.applicationAuthAudit(ctx, site.ID, provider.ID, "application_auth.denied", "")
		http.Error(rec, message, status)
	}
	return true
}
func (a *App) serveLDAPLogin(w http.ResponseWriter, r *http.Request, access applicationAccess, p storedIdentityProvider) error {
	if r.Method == "GET" {
		if e := a.applicationLoginLimit(r, p.ID, ""); e != nil {
			return e
		}
		browser := token()
		applicationCookie(w, applicationFlowCookie, browser, 600)
		applicationPage(w, 200, "Sign in", p.Settings.Name, applicationAuthPrefix+"login", hash(browser), safeApplicationReturn(r.URL.Query().Get("return")), "Sign in", true)
		return nil
	}
	if r.Method != "POST" {
		return apiError{405, "method not allowed"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if e := r.ParseForm(); e != nil {
		return apiError{400, "invalid login form"}
	}
	cookie, e := r.Cookie(applicationFlowCookie)
	if e != nil || len(cookie.Value) > 128 || r.Header.Get("Origin") != access.Settings.PublicOrigin || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(hash(cookie.Value))) != 1 {
		return apiError{403, "login request expired; reload the sign-in page"}
	}
	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	if e = a.applicationLoginLimit(r, p.ID, username); e != nil {
		return e
	}
	release, e := a.identityWork(r)
	if e != nil {
		return e
	}
	defer release()
	identity, e := a.ldapIdentity(r.Context(), p, username, password)
	r.PostForm.Del("password")
	r.Form.Del("password")
	if e != nil {
		return apiError{401, "sign-in failed; check your credentials or contact the application administrator"}
	}
	session, e := a.createApplicationSession(r.Context(), access, p, identity, time.Time{})
	if e != nil {
		return e
	}
	applicationCookie(w, applicationSessionCookie, session, access.Settings.SessionMinutes*60)
	applicationCookie(w, applicationFlowCookie, "", -1)
	http.Redirect(w, r, access.Settings.PublicOrigin+safeApplicationReturn(r.PostForm.Get("return")), http.StatusSeeOther)
	return nil
}
func (a *App) serveApplicationLogout(w http.ResponseWriter, r *http.Request, access applicationAccess) error {
	cookie, e := r.Cookie(applicationSessionCookie)
	if e != nil {
		applicationPage(w, 200, "Signed out", "Your application session has ended.", "", "", "", "", false)
		return nil
	}
	if r.Method == "GET" {
		applicationPage(w, 200, "Sign out", "End this application's session. Your identity provider session is managed separately.", applicationAuthPrefix+"logout", hash(cookie.Value+":logout"), "/", "Sign out", false)
		return nil
	}
	if r.Method != "POST" {
		return apiError{405, "method not allowed"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if e = r.ParseForm(); e != nil {
		return invalid("invalid sign-out form")
	}
	if r.Header.Get("Origin") != access.Settings.PublicOrigin || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(hash(cookie.Value+":logout"))) != 1 {
		return apiError{403, "invalid sign-out request"}
	}
	if _, e = a.db.Exec(r.Context(), "DELETE FROM application_sessions WHERE token_hash=$1 AND site_id=$2", hash(cookie.Value), access.SiteID); e != nil {
		return e
	}
	applicationCookie(w, applicationSessionCookie, "", -1)
	applicationPage(w, 200, "Signed out", "Your application session has ended.", "", "", "", "", false)
	return nil
}
