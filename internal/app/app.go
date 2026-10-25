package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/maxminddb-golang/v2"
)

//go:embed schema.sql
var schema string

type Site struct {
	Policies      []sitePolicySummary `json:"policies,omitempty"`
	Headers       *HeaderSettings     `json:"headers,omitempty"`
	Protection    *ProtectionSettings `json:"protection,omitempty"`
	ID            int64               `json:"id"`
	Name          string              `json:"name"`
	Hostnames     []string            `json:"hostnames"`
	Upstream      string              `json:"upstream"`
	CertificateID *int64              `json:"certificate_id"`
	RedirectHTTPS bool                `json:"redirect_https"`
	PreserveHost  bool                `json:"preserve_host"`
	Enabled       bool                `json:"enabled"`
}
type route struct {
	site  Site
	proxy *httputil.ReverseProxy
	cert  *tls.Certificate
}
type sitePolicySummary struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Mode        string   `json:"mode"`
	Revision    int64    `json:"revision"`
	SourceCIDRs []string `json:"source_cidrs"`
	Priority    int      `json:"priority"`
}
type snapshot struct {
	geoData        []byte
	policyBindings map[int64][]compiledPolicyBinding
	certificates   map[int64]*tls.Certificate
	version        int64
	routes         map[string]*route
	rules          map[int64][]compiledRule
	capture        map[int64]*capturePolicy
	protection     map[int64]*protectionPolicy
	geo            *maxminddb.Reader
}
type accessEvent struct {
	prepareEvidence          func() *evidenceEvent
	releaseEvidence          func()
	geo                      *maxminddb.Reader
	clientIP                 netip.Addr
	policyID, policyRevision int64
	policyName               string
	at                       time.Time
	site                     int64
	method                   string
	status                   int
	duration                 int64
	peer                     string
	results                  []RuleResult
	evidence                 *evidenceEvent
	country                  string
	blocked                  bool
	signals                  []string
	exemptions               []string
}
type App struct {
	cacheMu                       sync.Mutex
	cacheAt                       time.Time
	cacheVersion                  int64
	cacheAvailable, cacheRestored atomic.Bool
	workerPanics                  atomic.Uint64
	system                        systemSampler
	captureSlots                  chan struct{}
	evidenceDropped               atomic.Uint64
	flood                         floodLimiter
	metrics                       liveMetrics
	replicaID                     string
	feedHTTP                      http.RoundTripper
	dnsFactory                    func(context.Context, string, *http.Client) (*cloudflareChallenge, error)
	dnsWait                       func(context.Context, string, string) error
	dnsTransport                  http.RoundTripper
	cfg                           Config
	db                            *pgxpool.Pool
	active                        atomic.Pointer[snapshot]
	dbOK                          atomic.Bool
	initialized                   atomic.Bool
	access                        chan accessEvent
	dropped                       atomic.Uint64
}

func New(ctx context.Context, cfg Config) (*App, error) {
	pc, e := pgxpool.ParseConfig(cfg.DatabaseURL)
	if e != nil {
		return nil, errors.New("invalid DATABASE_URL")
	}
	pc.MaxConns = 20
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	db, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return nil, errors.New("database pool initialization failed")
	}
	a := &App{captureSlots: make(chan struct{}, 64), replicaID: token(), cfg: cfg, db: db, access: make(chan accessEvent, 8192)}
	if cfg.SnapshotCacheFile != "" {
		if e := a.restoreSnapshotCache(); e != nil {
			slog.Warn("snapshot cache unavailable; database startup required")
		}
	}
	return a, nil
}
func (a *App) Close() { a.db.Close() }
func (a *App) initialize(ctx context.Context) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(700010)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, schema); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	a.initialized.Store(true)
	return nil
}
func (a *App) Background(ctx context.Context) {
	logDone := make(chan struct{})
	logCtx, cancelLogs := context.WithCancel(ctx)
	go func() { defer close(logDone); a.RunWorker(logCtx, "access-log", a.logWorker) }()
	defer func() { cancelLogs(); <-logDone }()
	ticker := time.NewTicker(a.cfg.Refresh)
	defer ticker.Stop()
	for {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		var e error
		if !a.initialized.Load() {
			e = a.initialize(c)
		}
		if e == nil {
			e = a.refresh(c)
		}
		a.dbOK.Store(e == nil)
		cancel()
		if e != nil {
			slog.Warn("database refresh unavailable; retaining last snapshot")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *App) refresh(ctx context.Context) error {
	tx, e := a.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var version int64
	if e = tx.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&version); e != nil {
		return e
	}
	if old := a.active.Load(); old != nil && old.version == version {
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		a.cacheRestored.Store(false)
		a.persistSnapshot(old)
		return nil
	}
	rows, e := tx.Query(ctx, "SELECT id,chain_pem,key_cipher,key_id FROM certificates WHERE chain_pem<>''")
	if e != nil {
		return e
	}
	certs := map[int64]*tls.Certificate{}
	for rows.Next() {
		var id int64
		var chain, kid string
		var enc []byte
		if e = rows.Scan(&id, &chain, &enc, &kid); e != nil {
			rows.Close()
			return e
		}
		if kid != a.cfg.KeyID {
			rows.Close()
			return errors.New("unknown encryption key identifier")
		}
		key, e := open(a.cfg.Key, kid+":certificate", enc)
		if e != nil {
			rows.Close()
			return e
		}
		pair, e := tls.X509KeyPair([]byte(chain), key)
		if e != nil {
			rows.Close()
			return e
		}
		pair.Leaf, e = x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			rows.Close()
			return e
		}
		certs[id] = &pair
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = tx.Query(ctx, "SELECT s.id,s.name,s.hostnames,s.upstream,s.certificate_id,s.redirect_https,s.preserve_host,s.enabled,coalesce(h.settings,'{}'::jsonb) FROM sites s LEFT JOIN proxy_headers h ON h.site_id=s.id WHERE s.enabled")
	if e != nil {
		return e
	}
	next := &snapshot{version: version, routes: map[string]*route{}, certificates: certs}
	for rows.Next() {
		var s Site
		var rawHeaders []byte
		if e = rows.Scan(&s.ID, &s.Name, &s.Hostnames, &s.Upstream, &s.CertificateID, &s.RedirectHTTPS, &s.PreserveHost, &s.Enabled, &rawHeaders); e != nil {
			rows.Close()
			return e
		}
		target, e := url.Parse(s.Upstream)
		if e != nil {
			rows.Close()
			return e
		}
		r := &route{site: s}
		if s.CertificateID != nil {
			r.cert = certs[*s.CertificateID]
		}
		var headers HeaderSettings
		if e = json.Unmarshal(rawHeaders, &headers); e != nil {
			rows.Close()
			return e
		}
		headers, e = normalizeHeaders(headers)
		if e != nil {
			rows.Close()
			return e
		}
		r.site.Headers = &headers
		r.proxy = newProxyWithHeaders(target, s.PreserveHost, headers)
		for _, h := range s.Hostnames {
			next.routes[h] = r
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if e = a.loadPolicies(ctx, tx, next); e != nil {
		return e
	}
	if e = a.loadProtection(ctx, tx, next); e != nil {
		return e
	}
	if e = a.loadPolicyBindings(ctx, tx, next); e != nil {
		return e
	}
	if e = a.loadGeo(ctx, tx, next); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	old := a.active.Swap(next)
	a.cacheRestored.Store(false)
	a.persistSnapshot(next)
	if old != nil {
		for _, r := range old.routes {
			if tr, ok := r.proxy.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
		}
	}
	return nil
}
func newProxy(target *url.URL, preserve bool) *httputil.ReverseProxy {
	return newProxyWithHeaders(target, preserve, HeaderSettings{})
}
func newProxyWithHeaders(target *url.URL, preserve bool, settings HeaderSettings) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{BufferPool: &forwardingBuffers, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		rewriteProxyHeaders(pr, settings)
		if preserve {
			pr.Out.Host = pr.In.Host
		}
	}, ModifyResponse: func(response *http.Response) error { settings.applyResponse(response.Header); return nil }, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 200, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}}
	return p
}
func requestHost(raw string) string {
	h := raw
	if v, _, e := net.SplitHostPort(raw); e == nil {
		h = v
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
func (a *App) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s := a.active.Load()
		if s == nil {
			return nil, errors.New("configuration unavailable")
		}
		r := s.routes[requestHost(hello.ServerName)]
		if r == nil || r.cert == nil {
			return nil, errors.New("no certificate for SNI")
		}
		now := time.Now()
		if now.Before(r.cert.Leaf.NotBefore) || !now.Before(r.cert.Leaf.NotAfter) {
			return nil, errors.New("certificate is not currently valid")
		}
		return r.cert, nil
	}}
}
func (a *App) Public(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		a.challenge(w, r)
		return
	}
	s := a.active.Load()
	if s == nil {
		http.Error(w, "configuration unavailable", 503)
		return
	}
	rt := s.routes[requestHost(r.Host)]
	if rt == nil {
		http.Error(w, "unknown hostname", 421)
		return
	}
	if r.TLS != nil && requestHost(r.TLS.ServerName) != requestHost(r.Host) {
		http.Error(w, "SNI and Host must match", 421)
		return
	}
	start := time.Now()
	rec := &statusWriter{ResponseWriter: w, status: 200, beforeHeader: rt.site.Headers.applyResponse, onHijack: func(c net.Conn) net.Conn {
		return &trackedConnection{Conn: c, closed: func() { a.ConnectionState(c, http.StateClosed) }}
	}}
	policy := s.protection[rt.site.ID]
	clientIP, reliableIdentity := policy.resolveClientIP(r)
	selected := selectPolicy(s.policyBindings[rt.site.ID], clientIP, reliableIdentity)
	activeRules := s.rules[rt.site.ID]
	var policyID, policyRevision int64
	var policyName string
	if selected != nil {
		policy = selected.Protection
		activeRules = selected.Rules
		policyID = selected.ID
		policyRevision = selected.Revision
		policyName = selected.Name
	}
	exemptions := []string{}
	if reliableIdentity {
		exemptions = policy.exemptions(clientIP)
	}
	signals, protectionBlocked, protectionStatus := a.protectResolved(policy, rt.site.ID, r, clientIP, start, reliableIdentity)
	done := a.metrics.begin(r, rt.site.ID)
	defer done()
	facts := newRequestFacts(r)
	facts.facts["client_ip"] = Fact{State: "present", Values: []string{clientIP.String()}}
	results, blocked := evaluateRules(activeRules, facts, start)
	evidence := a.deferEvidence(s.capture[rt.site.ID], facts, results, start, rt.site.ID)
	defer func() {
		peer := clientIP.String()
		event := accessEvent{at: time.Now(), site: rt.site.ID, method: r.Method, status: rec.status, duration: time.Since(start).Milliseconds(), peer: peer, results: results, geo: s.geo, clientIP: clientIP, blocked: blocked || protectionBlocked, signals: signals, exemptions: exemptions, policyID: policyID, policyRevision: policyRevision, policyName: policyName}
		if len(a.access) >= cap(a.access) {
			evidence.discard()
			a.dropped.Add(1)
			return
		}
		event.prepareEvidence = evidence.finish()
		if evidence != nil {
			event.releaseEvidence = evidence.release
		}
		select {
		case a.access <- event:
		default:
			evidence.release()
			a.dropped.Add(1)
		}
	}()
	if protectionBlocked {
		rec.Header().Set("Cache-Control", "no-store")
		if protectionStatus == 429 {
			rec.Header().Set("Retry-After", "1")
		}
		http.Error(rec, "request blocked by gateway protection", protectionStatus)
		return
	}
	if blocked {
		rec.Header().Set("Cache-Control", "no-store")
		http.Error(rec, "request blocked by gateway policy", http.StatusForbidden)
		return
	}
	if r.TLS == nil && rt.site.RedirectHTTPS {
		http.Redirect(rec, r, "https://"+requestHost(r.Host)+r.URL.RequestURI(), http.StatusPermanentRedirect)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), proxyIdentityKey{}, proxyIdentity{clientIP, policy.forwardedProto(r)}))
	rt.proxy.ServeHTTP(rec, r)
}

type statusWriter struct {
	http.ResponseWriter
	status       int
	wrote        bool
	onHijack     func(net.Conn) net.Conn
	beforeHeader func(http.Header)
}

func (w *statusWriter) WriteHeader(n int) {
	if !w.wrote && n >= 200 {
		w.status = n
		w.wrote = true
		if w.beforeHeader != nil {
			w.beforeHeader(w.Header())
		}
	}
	w.ResponseWriter.WriteHeader(n)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, e := http.NewResponseController(w.ResponseWriter).Hijack()
	if e == nil {
		w.status = http.StatusSwitchingProtocols
		w.wrote = true
	}
	if e == nil && w.onHijack != nil {
		conn = w.onHijack(conn)
	}
	return conn, buffer, e
}

type trackedConnection struct {
	net.Conn
	once   sync.Once
	closed func()
}

func (c *trackedConnection) Close() error           { err := c.Conn.Close(); c.once.Do(c.closed); return err }
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (a *App) challenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	t := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if len(t) > 256 || strings.ContainsAny(t, "/\r\n") {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var response string
	e := a.db.QueryRow(ctx, "SELECT response FROM acme_challenges WHERE hostname=$1 AND token=$2 AND expires_at>now()", requestHost(r.Host), t).Scan(&response)
	if errors.Is(e, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if e != nil {
		http.Error(w, "challenge store unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, response)
}
func (a *App) logWorker(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batch := make([]accessEvent, 0, 1000)
	defer func() {
		a.dropped.Add(uint64(len(batch)))
		for n := range batch {
			if batch[n].releaseEvidence != nil {
				batch[n].releaseEvidence()
			}
		}
	}()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := a.storeAccessBatch(c, batch); e != nil {
			a.dropped.Add(uint64(len(batch)))
			slog.Warn("access/evidence log batch unavailable")
		}

		batch = batch[:0]
	}
	for {
		select {
		case e := <-a.access:
			batch = append(batch, e)
			if len(batch) == 1000 {
				flush()
			}
		case <-tick.C:
			flush()
			if a.initialized.Load() {
				a.publishMetrics(ctx)
			}
			if a.initialized.Load() {
				cleanup, cancel := context.WithTimeout(ctx, time.Second)
				_, _ = a.db.Exec(cleanup, "DELETE FROM traffic_evidence WHERE id IN (SELECT id FROM traffic_evidence WHERE expires_at<=now() LIMIT 1000)")
				cancel()
			}
		case <-ctx.Done():
			for {
				select {
				case e := <-a.access:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}
