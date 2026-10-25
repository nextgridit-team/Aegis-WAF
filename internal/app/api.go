package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

//go:embed assets/*
var assets embed.FS

type apiError struct {
	status  int
	message string
}

func (e apiError) Error() string { return e.message }
func invalid(s string) error     { return apiError{400, s} }
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return apiError{415, "Content-Type must be application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return invalid("invalid JSON request")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return invalid("provide one JSON object")
	}
	return nil
}
func hash(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }

type identity struct {
	ID             int64
	Username, CSRF string
}
type endpoint func(http.ResponseWriter, *http.Request, identity) error

func (a *App) wrap(auth bool, fn endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		w.Header().Set("Cache-Control", "no-store")
		var who identity
		var e error
		if auth {
			var cookie *http.Cookie
			cookie, e = r.Cookie("aegis_waf_session")
			if e != nil {
				respond(w, 401, map[string]string{"error": "authentication required"})
				return
			}
			e = a.db.QueryRow(ctx, "SELECT a.id,a.username,s.csrf FROM sessions s JOIN administrators a ON a.id=s.admin_id WHERE s.token_hash=$1 AND s.expires_at>now()", hash(cookie.Value)).Scan(&who.ID, &who.Username, &who.CSRF)
			if errors.Is(e, pgx.ErrNoRows) {
				respond(w, 401, map[string]string{"error": "session expired"})
				return
			}
			if e != nil {
				respond(w, 503, map[string]string{"error": "session store unavailable"})
				return
			}
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, er := url.Parse(origin)
				if er != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					respond(w, 403, map[string]string{"error": "origin rejected"})
					return
				}
			}
			if r.Header.Get("X-Requested-With") != "aegis-waf" {
				respond(w, 403, map[string]string{"error": "same-origin request header required"})
				return
			}
			if auth && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(who.CSRF)) != 1 {
				respond(w, 403, map[string]string{"error": "CSRF token rejected"})
				return
			}
		}
		e = fn(w, r, who)
		if e != nil {
			var ae apiError
			if errors.As(e, &ae) {
				respond(w, ae.status, map[string]string{"error": ae.message})
			} else {
				respond(w, 503, map[string]string{"error": "operation failed; database or certificate authority unavailable"})
			}
		}
	}
}
func (a *App) Management() http.Handler {
	m := http.NewServeMux()
	dashboardAPI(a, m)
	aiAPI(a, m)
	policyAPI(a, m)
	feedAPI(a, m)
	m.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]bool{"alive": true}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.active.Load() == nil {
			respond(w, 503, map[string]bool{"ready": false})
			return
		}
		respond(w, 200, map[string]bool{"ready": true})
	})
	m.HandleFunc("GET /api/setup", a.wrap(false, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		var count int
		e := a.db.QueryRow(r.Context(), "SELECT count(*) FROM administrators").Scan(&count)
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"setup_required": count == 0})
		return nil
	}))
	m.HandleFunc("POST /api/setup", a.wrap(false, a.setup))
	m.HandleFunc("POST /api/login", a.wrap(false, a.login))
	m.HandleFunc("POST /api/logout", a.wrap(true, a.logout))
	m.HandleFunc("GET /api/me", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		respond(w, 200, map[string]string{"username": i.Username, "csrf": i.CSRF})
		return nil
	}))
	m.HandleFunc("GET /api/status", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		var v int64
		if s := a.active.Load(); s != nil {
			v = s.version
		}
		respond(w, 200, map[string]any{"configuration_version": v, "database_available": a.dbOK.Load(), "propagation_seconds": a.cfg.Refresh.Seconds(), "dropped_evidence_samples": a.evidenceDropped.Load(), "dropped_access_logs": a.dropped.Load()})
		return nil
	}))
	m.HandleFunc("GET /api/sites", a.wrap(true, a.listSites))
	m.HandleFunc("POST /api/sites", a.wrap(true, a.saveSite))
	m.HandleFunc("PUT /api/sites/{id}", a.wrap(true, a.saveSite))
	m.HandleFunc("DELETE /api/sites/{id}", a.wrap(true, a.deleteSite))
	m.HandleFunc("GET /api/certificates", a.wrap(true, a.listCertificates))
	m.HandleFunc("POST /api/certificates", a.wrap(true, a.upload))
	m.HandleFunc("PUT /api/certificates/{id}", a.wrap(true, a.upload))
	m.HandleFunc("DELETE /api/certificates/{id}", a.wrap(true, a.deleteCertificate))
	m.HandleFunc("GET /api/acme/directory", a.wrap(true, a.directoryTerms))
	m.HandleFunc("GET /api/acme/accounts", a.wrap(true, a.listAccounts))
	m.HandleFunc("POST /api/acme/accounts", a.wrap(true, a.registerAccount))
	m.HandleFunc("POST /api/acme/certificates", a.wrap(true, a.issue))
	m.HandleFunc("GET /api/acme/jobs", a.wrap(true, a.listJobs))
	m.HandleFunc("POST /api/acme/jobs/{id}/retry", a.wrap(true, a.retryJob))
	m.HandleFunc("GET /api/audit", a.wrap(true, a.listAudit))
	m.HandleFunc("GET /api/access-logs", a.wrap(true, a.listAccess))
	ruleAPI(a, m)
	dnsAPI(a, m)
	f, _ := fs.Sub(assets, "assets")
	m.Handle("GET /", http.FileServer(http.FS(f)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		m.ServeHTTP(w, r)
	})
}
func (a *App) throttle(ctx context.Context, bucket string, limit int, window time.Duration) error {
	var n int
	e := a.db.QueryRow(ctx, `INSERT INTO login_limits(bucket,attempts,expires_at) VALUES($1,1,now()+$2::interval) ON CONFLICT(bucket) DO UPDATE SET attempts=CASE WHEN login_limits.expires_at<now() THEN 1 ELSE login_limits.attempts+1 END,expires_at=CASE WHEN login_limits.expires_at<now() THEN excluded.expires_at ELSE login_limits.expires_at END RETURNING attempts`, bucket, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&n)
	if e != nil {
		return e
	}
	if n > limit {
		return apiError{429, "too many attempts; try again later"}
	}
	return nil
}
func (a *App) authLimit(r *http.Request) error {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if e := a.throttle(r.Context(), "peer:"+hash(peer), 20, 10*time.Minute); e != nil {
		return e
	}
	return a.throttle(r.Context(), "global", 200, time.Minute)
}
func audit(ctx context.Context, tx pgx.Tx, actor, action, resource string) error {
	_, e := tx.Exec(ctx, "INSERT INTO audit_events(actor,action,resource) VALUES($1,$2,$3)", actor, action, resource)
	return e
}
func (a *App) setup(w http.ResponseWriter, r *http.Request, _ identity) error {
	if e := a.authLimit(r); e != nil {
		return e
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Secret   string `json:"secret"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	// Deployment secret files already trim surrounding whitespace; pasted codes do too.
	provided, expected := sha256.Sum256([]byte(strings.TrimSpace(body.Secret))), sha256.Sum256([]byte(a.cfg.BootstrapSecret))
	if subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
		return apiError{403, "bootstrap secret rejected"}
	}
	if len(body.Username) < 3 || len(body.Username) > 64 || strings.TrimSpace(body.Username) != body.Username || len(body.Password) < 14 || len(body.Password) > 72 {
		return invalid("username must be 3–64 characters; password must be 14–72 bytes")
	}
	pw, e := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(700011)"); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM administrators").Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return apiError{409, "administrator setup is already complete"}
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO administrators(username,password_hash) VALUES($1,$2)", body.Username, string(pw)); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, body.Username, "administrator.bootstrap", "administrator"); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 201, map[string]bool{"created": true})
	return nil
}

var dummyPassword, _ = bcrypt.GenerateFromPassword([]byte("invalid-login-timing-placeholder"), 12)

func (a *App) login(w http.ResponseWriter, r *http.Request, _ identity) error {
	if e := a.authLimit(r); e != nil {
		return e
	}
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if len(b.Username) > 64 || len(b.Password) > 72 {
		return apiError{401, "invalid credentials"}
	}
	var id int64
	var pw string
	e := a.db.QueryRow(r.Context(), "SELECT id,password_hash FROM administrators WHERE username=$1", b.Username).Scan(&id, &pw)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if errors.Is(e, pgx.ErrNoRows) {
		pw = string(dummyPassword)
	}
	match := bcrypt.CompareHashAndPassword([]byte(pw), []byte(b.Password))
	if e != nil || match != nil {
		_, er := a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES('unauthenticated','login.failed','management')")
		if er != nil {
			return er
		}
		return apiError{401, "invalid credentials"}
	}
	t, csrf := token(), token()
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "INSERT INTO sessions(token_hash,admin_id,csrf,expires_at) VALUES($1,$2,$3,now()+interval '12 hours')", hash(t), id, csrf); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, b.Username, "login.succeeded", "management"); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	http.SetCookie(w, sessionCookie(r, t, 43200))
	respond(w, 200, map[string]string{"csrf": csrf, "username": b.Username})
	return nil
}
func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	h := requestHost(r.Host)
	loopback := h == "localhost"
	if ip := net.ParseIP(h); ip != nil {
		loopback = ip.IsLoopback()
	}
	return &http.Cookie{Name: "aegis_waf_session", Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || !loopback, MaxAge: maxAge}
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, i identity) error {
	c, _ := r.Cookie("aegis_waf_session")
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hash(c.Value)); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "logout", "management"); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	http.SetCookie(w, sessionCookie(r, "", -1))
	respond(w, 200, map[string]bool{"logged_out": true})
	return nil
}
func (a *App) list(w http.ResponseWriter, r *http.Request, sql string) error {
	var data []byte
	if e := a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM ("+sql+") x").Scan(&data); e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(data))
	return nil
}
func (a *App) listSites(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, "SELECT s.*,p.settings AS protection,h.settings AS headers,coalesce((SELECT jsonb_agg(jsonb_build_object('id',pol.id,'name',pol.spec->>'name','mode',pol.spec->>'mode','revision',pol.revision,'source_cidrs',b.source_cidrs,'priority',b.priority) ORDER BY b.priority) FROM policy_assignments b JOIN policies pol ON pol.id=b.policy_id WHERE b.site_id=s.id),'[]'::jsonb) AS policies FROM sites s LEFT JOIN protection_settings p ON p.site_id=s.id LEFT JOIN proxy_headers h ON h.site_id=s.id ORDER BY s.id")
}
func (a *App) listCertificates(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, `SELECT c.id,c.name,c.origin,c.domains,c.issuer,c.not_before,c.not_after,c.account_id,c.challenge_type,c.dns_credential_id,c.updated_at,EXISTS(SELECT 1 FROM dns_challenges d JOIN jobs j ON j.id=d.job_id WHERE j.certificate_id=c.id) AS pending_dns_cleanup,CASE WHEN c.not_before IS NULL THEN 'pending' WHEN now()<c.not_before THEN 'not yet valid' WHEN now()>=c.not_after THEN 'expired' ELSE 'valid' END AS validity,coalesce((SELECT jsonb_agg(jsonb_build_object('id',s.id,'name',s.name)) FROM sites s WHERE s.certificate_id=c.id),'[]'::jsonb) AS assigned_sites FROM certificates c ORDER BY c.id`)
}
func (a *App) listAccounts(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, "SELECT id,directory,email,account_url,tos_accepted_at FROM acme_accounts ORDER BY id")
}
func (a *App) listJobs(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, `SELECT j.id,j.certificate_id,c.name,j.status,j.attempts,j.next_attempt,j.error,j.updated_at,coalesce((SELECT jsonb_agg(jsonb_build_object('url',o.url,'status',o.status,'error',o.error)) FROM acme_orders o WHERE o.job_id=j.id),'[]'::jsonb) AS orders FROM jobs j JOIN certificates c ON c.id=j.certificate_id ORDER BY j.id DESC LIMIT 100`)
}
func (a *App) listAudit(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, "SELECT * FROM audit_events ORDER BY id DESC LIMIT 200")
}
func (a *App) listAccess(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, "SELECT * FROM access_logs ORDER BY id DESC LIMIT 200")
}
func resourceID(r *http.Request) (int64, error) {
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id < 1 {
		return 0, invalid("invalid resource id")
	}
	return id, nil
}
func (a *App) change(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT version FROM config_version WHERE id FOR UPDATE"); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id"); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *App) saveSite(w http.ResponseWriter, r *http.Request, i identity) error {
	var s Site
	if e := decode(w, r, &s); e != nil {
		return e
	}
	if s.Headers != nil {
		normalized, e := normalizeHeaders(*s.Headers)
		if e != nil {
			return e
		}
		s.Headers = &normalized
	}
	if s.Protection != nil {
		compiled, e := compileProtection(*s.Protection)
		if e != nil {
			return e
		}
		s.Protection = &compiled.ProtectionSettings
	}
	if len(strings.TrimSpace(s.Name)) == 0 || len(s.Name) > 120 {
		return invalid("site name must be 1–120 characters")
	}
	var e error
	s.Hostnames, e = domains(s.Hostnames)
	if e != nil {
		return invalid(e.Error())
	}
	if e = validateUpstream(s.Upstream); e != nil {
		return invalid(e.Error())
	}
	if s.RedirectHTTPS && s.CertificateID == nil {
		return invalid("attach a valid certificate before enabling HTTPS redirect")
	}
	if r.Method == "PUT" {
		s.ID, e = resourceID(r)
		if e != nil {
			return e
		}
	} else {
		s.ID = 0
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		if s.CertificateID != nil {
			var chain string
			e := tx.QueryRow(r.Context(), "SELECT chain_pem FROM certificates WHERE id=$1", *s.CertificateID).Scan(&chain)
			if errors.Is(e, pgx.ErrNoRows) {
				return invalid("certificate not found")
			}
			if e != nil {
				return e
			}
			b, _ := pemLeaf(chain)
			if b == nil || time.Now().Before(b.NotBefore) || !time.Now().Before(b.NotAfter) {
				return invalid("attach a currently valid certificate")
			}
			if e = covers(b, s.Hostnames); e != nil {
				return invalid(e.Error())
			}
		}
		for _, h := range s.Hostnames {
			var exists bool
			if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM site_hosts WHERE hostname=$1 AND site_id<>$2)", h, s.ID).Scan(&exists); e != nil {
				return e
			}
			if exists {
				return apiError{409, "hostname is already assigned to another site"}
			}
		}
		if s.ID == 0 {
			if e := tx.QueryRow(r.Context(), "INSERT INTO sites(name,hostnames,upstream,certificate_id,redirect_https,preserve_host,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id", s.Name, s.Hostnames, s.Upstream, s.CertificateID, s.RedirectHTTPS, s.PreserveHost, s.Enabled).Scan(&s.ID); e != nil {
				return e
			}
		} else {
			tag, e := tx.Exec(r.Context(), "UPDATE sites SET name=$2,hostnames=$3,upstream=$4,certificate_id=$5,redirect_https=$6,preserve_host=$7,enabled=$8 WHERE id=$1", s.ID, s.Name, s.Hostnames, s.Upstream, s.CertificateID, s.RedirectHTTPS, s.PreserveHost, s.Enabled)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 0 {
				return apiError{404, "site not found"}
			}
		}
		if _, e := tx.Exec(r.Context(), "DELETE FROM site_hosts WHERE site_id=$1", s.ID); e != nil {
			return e
		}
		for _, h := range s.Hostnames {
			if _, e := tx.Exec(r.Context(), "INSERT INTO site_hosts(hostname,site_id) VALUES($1,$2)", h, s.ID); e != nil {
				return e
			}
		}
		if s.Protection != nil {
			raw, _ := json.Marshal(s.Protection)
			if _, e := tx.Exec(r.Context(), "INSERT INTO protection_settings(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", s.ID, raw); e != nil {
				return e
			}
			if e := audit(r.Context(), tx, i.Username, "protection.saved", strconv.FormatInt(s.ID, 10)); e != nil {
				return e
			}
		}
		if s.Headers != nil {
			raw, _ := json.Marshal(s.Headers)
			if e := storeHeaderSettings(r.Context(), tx, s.ID, raw); e != nil {
				return e
			}
			if e := audit(r.Context(), tx, i.Username, "proxy.headers.saved", strconv.FormatInt(s.ID, 10)); e != nil {
				return e
			}
		}
		return audit(r.Context(), tx, i.Username, "site.saved", strconv.FormatInt(s.ID, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, s)
	return nil
}
func (a *App) deleteSite(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(r.Context(), "DELETE FROM sites WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return apiError{404, "site not found"}
		}
		return audit(r.Context(), tx, i.Username, "site.deleted", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
