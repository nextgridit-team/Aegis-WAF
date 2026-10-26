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
	TrafficProfile    string              `json:"traffic_profile"`
	StreamWindowBytes int                 `json:"stream_window_bytes"`
	Policies          []sitePolicySummary `json:"policies,omitempty"`
	Headers           *HeaderSettings     `json:"headers,omitempty"`
	Protection        *ProtectionSettings `json:"protection,omitempty"`
	ID                int64               `json:"id"`
	Name              string              `json:"name"`
	Hostnames         []string            `json:"hostnames"`
	Upstream          string              `json:"upstream"`
	CertificateID     *int64              `json:"certificate_id"`
	RedirectHTTPS     bool                `json:"redirect_https"`
	PreserveHost      bool                `json:"preserve_host"`
	Enabled           bool                `json:"enabled"`
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
	rateState      *sharedRateState
	localGeo       *localGeoPolicy
	managedSets    map[string]signatureSet
	managedWAFs    map[string]*managedSignatureRuntime
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
	localGeo                                             *localGeoPolicy
	observedCountry, locationSource, locationReferenceIP string
	securityDisabled, securitySamples                    bool
	responseSource                                       string
	regions                                              *regionCache
	regionCode, regionName                               string
	network                                              networkAccessResult
	managed                                              managedSignatureResult
	bot                                                  botResult
	prepareEvidence                                      func() *evidenceEvent
	releaseEvidence                                      func()
	geo                                                  *maxminddb.Reader
	clientIP                                             netip.Addr
	policyID, policyRevision                             int64
	policyName                                           string
	at                                                   time.Time
	site                                                 int64
	method                                               string
	status                                               int
	duration                                             int64
	peer                                                 string
	results                                              []RuleResult
	evidence                                             *evidenceEvent
	country                                              string
	blocked                                              bool
	signals                                              []string
	exemptions                                           []string
}
type App struct {
	prom                          *gatewayTelemetry
	publicIPHTTP                  http.RoundTripper
	regions                       atomic.Pointer[regionCache]
	geoHTTP                       http.RoundTripper
	managedSlots                  chan struct{}
	cacheMu                       sync.Mutex
	cacheAt                       time.Time
	cacheVersion                  int64
	cacheAvailable, cacheRestored atomic.Bool
	workerPanics                  atomic.Uint64
	system                        systemSampler
	captureSlots                  chan struct{}
	evidenceDropped               atomic.Uint64
	flood                         floodLimiter
	botRates                      floodLimiter
	botWork                       chan struct{}
	simulationWork                chan struct{}
	botClearances                 botClearanceCache
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
	a := &App{simulationWork: make(chan struct{}, 2), botWork: make(chan struct{}, 8), managedSlots: make(chan struct{}, 64), captureSlots: make(chan struct{}, 64), replicaID: token(), cfg: cfg, db: db, access: make(chan accessEvent, 8192)}
	a.prom = newGatewayTelemetry(a)
	if cfg.SnapshotCacheFile != "" {
		if e := a.restoreSnapshotCache(); e != nil {
			slog.Warn("snapshot cache unavailable; database startup required")
		}
	}
	return a, nil
}
func (a *App) Close() {
	if s := a.active.Load(); s != nil {
		s.rateState.retire()
	}
	a.db.Close()
}
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
	if e = seedBaselinePolicy(ctx, tx); e != nil {
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
	next, e := a.buildSnapshot(ctx, tx, version)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	old := a.active.Swap(next)
	if old != nil && old.rateState != next.rateState {
		old.rateState.retire()
	}
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

// buildSnapshot compiles a complete candidate without committing database state
// or changing the active pointer. Refresh and offline simulation share it.
func (a *App) buildSnapshot(ctx context.Context, tx pgx.Tx, version int64) (*snapshot, error) {
	rows, e := tx.Query(ctx, "SELECT id,chain_pem,key_cipher,key_id FROM certificates WHERE chain_pem<>''")
	if e != nil {
		return nil, e
	}
	certs := map[int64]*tls.Certificate{}
	for rows.Next() {
		var id int64
		var chain, kid string
		var enc []byte
		if e = rows.Scan(&id, &chain, &enc, &kid); e != nil {
			rows.Close()
			return nil, e
		}
		if kid != a.cfg.KeyID {
			rows.Close()
			return nil, errors.New("unknown encryption key identifier")
		}
		key, e := open(a.cfg.Key, kid+":certificate", enc)
		if e != nil {
			rows.Close()
			return nil, e
		}
		pair, e := tls.X509KeyPair([]byte(chain), key)
		if e != nil {
			rows.Close()
			return nil, e
		}
		pair.Leaf, e = x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			rows.Close()
			return nil, e
		}
		certs[id] = &pair
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = tx.Query(ctx, "SELECT s.id,s.name,s.hostnames,s.upstream,s.certificate_id,s.redirect_https,s.preserve_host,s.enabled,s.traffic_profile,s.stream_window_bytes,coalesce(h.settings,'{}'::jsonb) FROM sites s LEFT JOIN proxy_headers h ON h.site_id=s.id WHERE s.enabled")
	if e != nil {
		return nil, e
	}
	next := &snapshot{version: version, routes: map[string]*route{}, certificates: certs}
	for rows.Next() {
		var s Site
		var rawHeaders []byte
		if e = rows.Scan(&s.ID, &s.Name, &s.Hostnames, &s.Upstream, &s.CertificateID, &s.RedirectHTTPS, &s.PreserveHost, &s.Enabled, &s.TrafficProfile, &s.StreamWindowBytes, &rawHeaders); e != nil {
			rows.Close()
			return nil, e
		}
		if e = normalizeSiteTraffic(&s); e != nil {
			rows.Close()
			return nil, e
		}
		target, e := url.Parse(s.Upstream)
		if e != nil {
			rows.Close()
			return nil, e
		}
		r := &route{site: s}
		if s.CertificateID != nil {
			r.cert = certs[*s.CertificateID]
		}
		var headers HeaderSettings
		if e = json.Unmarshal(rawHeaders, &headers); e != nil {
			rows.Close()
			return nil, e
		}
		headers, e = normalizeHeaders(headers)
		if e != nil {
			rows.Close()
			return nil, e
		}
		r.site.Headers = &headers
		r.proxy = newSiteProxy(target, s, headers)
		for _, h := range s.Hostnames {
			next.routes[h] = r
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = a.loadRateState(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadPolicies(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadProtection(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadPolicyBindings(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadManagedSignatures(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadGeo(ctx, tx, next); e != nil {
		return nil, e
	}
	if e = a.loadLocalGeo(ctx, tx, next); e != nil {
		return nil, e
	}
	return next, nil
}
func newProxy(target *url.URL, preserve bool) *httputil.ReverseProxy {
	return newProxyWithHeaders(target, preserve, HeaderSettings{})
}
func newProxyWithHeaders(target *url.URL, preserve bool, settings HeaderSettings) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{BufferPool: &forwardingBuffers, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		rewriteProxyHeaders(pr, settings)
		stripBotCookies(pr.Out)
		if state, _ := pr.In.Context().Value(managedResponseKey{}).(*managedResponseState); state != nil {
			pr.Out.Header.Set("Accept-Encoding", "identity")
		}
		if preserve {
			pr.Out.Host = pr.In.Host
		}
	}, ModifyResponse: func(response *http.Response) error {
		if err := inspectManagedResponse(response); err != nil {
			return err
		}
		settings.applyResponseSecurity(response.Header, forwardingIdentity(response.Request).Proto == "https")
		return nil
	}, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 200, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		var rejected managedResponseError
		if errors.As(e, &rejected) {
			if status, ok := w.(*statusWriter); ok {
				status.responseSource = "waf"
			}
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "upstream response rejected by managed signature protection", http.StatusBadGateway)
			return
		}
		if status, ok := w.(*statusWriter); ok {
			status.responseSource = "gateway_error"
		}
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
		rec := &statusWriter{ResponseWriter: w, status: 200}
		defer func() { a.prom.recordHTTP(rec.status, "acme", "allowed") }()
		a.challenge(rec, r)
		return
	}
	s := a.active.Load()
	if s == nil {
		a.prom.recordHTTP(503, "unrouted", "blocked")
		http.Error(w, "configuration unavailable", 503)
		return
	}
	rt := s.routes[requestHost(r.Host)]
	if rt == nil {
		a.prom.recordHTTP(421, "unrouted", "blocked")
		http.Error(w, "unknown hostname", 421)
		return
	}
	if r.TLS != nil && requestHost(r.TLS.ServerName) != requestHost(r.Host) {
		a.prom.recordHTTP(421, "unrouted", "blocked")
		http.Error(w, "SNI and Host must match", 421)
		return
	}
	if s.rateState != nil && s.rateState.stored.Settings.Backend == "redis" {
		r = r.WithContext(context.WithValue(r.Context(), rateStateKey{}, s.rateState))
	}
	start := time.Now()
	secureResponse := r.TLS != nil
	botOwnedResponse := strings.HasPrefix(r.URL.Path, botChallengePrefix)
	rec := &statusWriter{ResponseWriter: w, status: 200, responseSource: "waf", beforeHeader: func(h http.Header) {
		if botOwnedResponse {
			// Application header rewrites must not remove proof cookies, cache a
			// challenge or replace its CSP/content type. Retain host HSTS only.
			security := http.Header{}
			rt.site.Headers.applyResponseSecurity(security, secureResponse)
			if value := security.Get("Strict-Transport-Security"); value != "" {
				h.Set("Strict-Transport-Security", value)
			}
			return
		}
		rt.site.Headers.applyResponseSecurity(h, secureResponse)
	}, onHijack: func(c net.Conn) net.Conn {
		return &trackedConnection{Conn: c, closed: func() { a.ConnectionState(c, http.StateClosed) }}
	}}
	policy := s.protection[rt.site.ID]
	clientIP, reliableIdentity := policy.resolveClientIP(r)
	selected := selectPolicy(s.policyBindings[rt.site.ID], clientIP, reliableIdentity)
	activeRules := s.rules[rt.site.ID]
	var policyID, policyRevision int64
	var policyName string
	var managed *managedSignatureRuntime
	if selected != nil {
		policy = selected.Protection
		activeRules = selected.Rules
		policyID = selected.ID
		policyRevision = selected.Revision
		policyName = selected.Name
		managed = selected.Managed
	}
	secureResponse = secureResponse || policy.forwardedProto(r) == "https"
	exemptions := []string{}
	if reliableIdentity {
		exemptions = policy.exemptions(clientIP)
	}
	network := networkAccessResult{}
	if policy != nil {
		network = policy.network.evaluate(clientIP, reliableIdentity, func() string { return countryFor(s.geo, clientIP) })
	}
	botEndpoint := strings.HasPrefix(r.URL.Path, botChallengePrefix)
	botDecision := botResult{}
	botBlocked, botRequired := false, false
	var botReq botRequest
	signals := []string{}
	protectionBlocked, protectionStatus := false, 0
	if !network.Blocked && !network.BypassWAF {
		signals, protectionBlocked, protectionStatus = a.protectResolved(policy, rt.site.ID, r, clientIP, start, reliableIdentity)
	}
	if policy != nil && policy.BotChallenge.Enabled && policy.BotMode != "off" && !botEndpoint && !network.Blocked && !network.BypassWAF && !protectionBlocked && (!reliableIdentity || !matchesCIDRs(policy.botExempt, clientIP)) {
		botDecision = a.botScore(policy, rt.site.ID, r, clientIP, start, rt.site.TrafficProfile)
		if botDecision.StateUnavailable {
			signals = append(signals, "bot_rate_state_unavailable")
		}
		if botDecision.StateUnavailable && policy.BotMode == "block" {
			protectionBlocked = true
			protectionStatus = 503
			botDecision.Decision = "state_unavailable"
		} else if botDecision.Score >= botDecision.Threshold {
			if policy.BotMode == "observe" {
				botDecision.Decision = "observe"
				if rt.site.machineEndpoint() {
					signals = append(signals, "bot_would_block")
				} else {
					signals = append(signals, "bot_would_challenge")
				}
			} else if rt.site.machineEndpoint() {
				protectionBlocked, protectionStatus = true, http.StatusForbidden
				botDecision.Decision = "blocked"
				signals = append(signals, "bot_suspicion_blocked")
			} else {
				botReq = a.botContext(policy, rt.site.ID, policyID, policyRevision, r, clientIP, secureResponse)
				botReq.result = botDecision
				ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
				cleared, err := a.hasBotClearance(ctx, r, botReq)
				cancel()
				if err != nil {
					protectionBlocked = true
					protectionStatus = 503
					botDecision.Decision = "unavailable"
					signals = append(signals, "bot_verification_unavailable")
				} else if cleared {
					botDecision.Decision = "cleared"
				} else {
					botRequired = true
					botDecision.Decision = "challenge"
					signals = append(signals, "bot_challenge_required")
				}
			}
		}
	}
	if network.WouldBlock {
		signals = append(signals, network.Decision)
	}
	done := a.metrics.begin(r, rt.site.ID)
	defer done()
	facts := newRequestFacts(r)
	facts.facts[factKey("client_ip", "")] = Fact{State: "present", Values: []string{clientIP.String()}}
	results := []RuleResult{}
	blocked := false
	if !botEndpoint && !network.Blocked && !network.BypassWAF {
		results, blocked = evaluateRules(activeRules, facts, start)
	}
	capturePolicy := s.capture[rt.site.ID]
	if botEndpoint {
		capturePolicy = nil
	}
	evidence := a.deferEvidence(capturePolicy, facts, results, start, rt.site.ID)
	managedResult := managedSignatureResult{}
	managedBlocked, managedStatus := false, 0
	if !botEndpoint && managed != nil && !network.Blocked && !network.BypassWAF && !protectionBlocked && !blocked {
		if managed.Options.ResponseMode != "off" {
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			state := &managedResponseState{runtime: managed, result: &managedResult, blocked: &managedBlocked, cancel: cancel, app: a, site: rt.site, clientIP: clientIP, reliable: reliableIdentity}
			defer state.Close()
			r = r.WithContext(context.WithValue(ctx, managedResponseKey{}, state))
		}
		managedResult, managedBlocked, managedStatus = a.inspectManaged(managed, r, clientIP, reliableIdentity)
	}
	a.prom.observeInspection("request", time.Since(start))
	defer func() {
		if len(managedResult.RuleIDs) > 0 {
			signals = append(signals, "managed_signature")
		}
		if managedResult.Inspection != "" && managedResult.Inspection != "complete" && managedResult.Inspection != "headers" {
			signals = append(signals, "signature_inspection_incomplete")
		}
		switch v := managedResult.ResponseInspection; v {
		case "partial", "body_limit", "error", "read_error_or_timeout", "unsupported_encoding", "stream_busy", "stream_error", "stream_unavailable":
			signals = append(signals, "response_inspection_"+v)
		}

		peer := clientIP.String()
		event := accessEvent{localGeo: s.localGeo, responseSource: rec.responseSource, regions: a.regions.Load(), network: network, at: time.Now(), site: rt.site.ID, method: r.Method, status: rec.status, duration: time.Since(start).Milliseconds(), peer: peer, results: results, geo: s.geo, clientIP: clientIP, blocked: network.Blocked || blocked || protectionBlocked || managedBlocked || botBlocked, bot: botDecision, signals: signals, exemptions: exemptions, policyID: policyID, policyRevision: policyRevision, policyName: policyName, managed: managedResult}
		a.prom.observeEvent(event)
		if capture := s.capture[rt.site.ID]; capture != nil {
			event.securityDisabled = capture.Settings.SecurityEventsDisabled
			event.securitySamples = capture.Settings.SecuritySamples
		}
		if network.GeoChecked {
			event.country = network.Country
			event.geo = nil
		}
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
	if network.Blocked {
		rec.Header().Set("Cache-Control", "no-store")
		if rt.site.machineEndpoint() {
			rt.site.rejectRequest(rec, http.StatusForbidden, "network_access_denied")
		} else {
			http.Error(rec, "request blocked by network access policy", http.StatusForbidden)
		}
		return
	}
	if managedBlocked {
		rec.Header().Set("Cache-Control", "no-store")
		if rt.site.machineEndpoint() {
			rt.site.rejectRequest(rec, managedStatus, "managed_signature_rejected")
		} else {
			http.Error(rec, "request rejected by managed signature protection", managedStatus)
		}
		return
	}
	if protectionBlocked {
		rec.Header().Set("Cache-Control", "no-store")
		if protectionStatus == 429 {
			rec.Header().Set("Retry-After", "1")
		}
		if rt.site.machineEndpoint() {
			rt.site.rejectRequest(rec, protectionStatus, "gateway_protection_denied")
		} else {
			http.Error(rec, "request blocked by gateway protection", protectionStatus)
		}
		return
	}
	if blocked {
		rec.Header().Set("Cache-Control", "no-store")
		if rt.site.machineEndpoint() {
			rt.site.rejectRequest(rec, http.StatusForbidden, "policy_denied")
		} else {
			http.Error(rec, "request blocked by gateway policy", http.StatusForbidden)
		}
		return
	}
	if botEndpoint {
		if rt.site.machineEndpoint() {
			rt.site.rejectRequest(rec, http.StatusNotFound, "browser_verification_unavailable")
			return
		}
		if policy == nil {
			http.NotFound(rec, r)
			return
		}
		botReq = a.botContext(policy, rt.site.ID, policyID, policyRevision, r, clientIP, secureResponse)
		botDecision = a.serveBotEndpoint(rec, r, botReq, policy, reliableIdentity)
		botBlocked = botDecision.Decision == "failed"
		if botDecision.Decision == "passed" {
			signals = append(signals, "bot_challenge_passed")
		} else if botBlocked {
			signals = append(signals, "bot_challenge_failed")
		}
		return
	}
	if botRequired {
		botOwnedResponse = true
		botBlocked = true
		if !secureResponse && rt.site.CertificateID != nil {
			http.Redirect(rec, r, "https://"+requestHost(r.Host)+r.URL.RequestURI(), 308)
			return
		}
		a.requireBotChallenge(rec, r, botReq, reliableIdentity)
		return
	}
	if !secureResponse && rt.site.RedirectHTTPS {
		rec.responseSource = "redirect"
		http.Redirect(rec, r, "https://"+requestHost(r.Host)+r.URL.RequestURI(), http.StatusPermanentRedirect)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), proxyIdentityKey{}, proxyIdentity{clientIP, policy.forwardedProto(r)}))
	rec.responseSource = "upstream"
	rt.proxy.ServeHTTP(rec, r)
}

type statusWriter struct {
	responseSource string
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
		for n := range batch {
			batch[n].enrich()
			emitSecurityEvent(slog.Default(), batch[n])
		}
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
