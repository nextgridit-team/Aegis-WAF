package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSealedSnapshotCache(t *testing.T) {
	now := time.Now()
	chain, key := testCertificate(t, []string{"cached.test"}, 1, now.Add(-time.Hour), now.Add(time.Hour))
	pair, e := tls.X509KeyPair([]byte(chain), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Key: make([]byte, 32), KeyID: "primary", DatabaseURL: "postgres://cache-test", SnapshotCacheFile: filepath.Join(t.TempDir(), "snapshot"), SnapshotCacheMaxAge: time.Hour}
	a := &App{cfg: cfg}
	p, _ := compileProtection(defaultProtection())
	p.budgetScope = 3
	spec := probeRule("path", "", "equals", "/.env")
	rule, e := compileRule(spec)
	if e != nil {
		t.Fatal(e)
	}
	rule.ID = 1
	rule.Expires = now.Add(-time.Second)
	site := Site{ID: 1, Hostnames: []string{"cached.test"}, Upstream: "http://127.0.0.1:9", CertificateID: ptrInt64(1), Headers: &HeaderSettings{ResponseSet: map[string]string{"X-Cache": "restored"}}}
	site.UpstreamTLS = upstreamTLSSettings{TrustedCertsPEM: chain}
	s := &snapshot{version: 2, certificates: map[int64]*tls.Certificate{1: &pair}, routes: map[string]*route{"cached.test": {site: site}}, rules: map[int64][]compiledRule{1: {rule}}, capture: map[int64]*capturePolicy{}, protection: map[int64]*protectionPolicy{1: p}, policyBindings: map[int64][]compiledPolicyBinding{1: {{ID: 3, Revision: 2, Name: "External", Priority: 10000, Protection: p}}}}
	sealed, e := a.archiveSnapshot(s, now)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(sealed), "PRIVATE KEY") || strings.Contains(string(sealed), "cached.test") {
		t.Fatal("snapshot contains plaintext secrets/configuration")
	}
	restored, e := a.decodeSnapshot(sealed, now)
	if e != nil {
		t.Fatal(e)
	}
	if restored.routes["cached.test"].site.UpstreamTLS.TrustedCertsPEM != chain {
		t.Fatal("cached upstream trust lost")
	}
	if restored.routes["cached.test"].cert == nil || restored.policyBindings[1][0].ID != 3 || restored.routes["cached.test"].site.Headers.ResponseSet["X-Cache"] != "restored" {
		t.Fatal("snapshot configuration lost")
	}
	if selected := selectPolicy(restored.policyBindings[1], netip.MustParseAddr("203.0.113.1"), true); selected == nil || selected.Protection.budgetScope != 3 {
		t.Fatal("restored policy scope lost")
	}
	results, _ := evaluateRules(restored.rules[1], newRequestFacts(httptest.NewRequest("GET", "http://cached.test/.env", nil)), now)
	if len(results) != 0 {
		t.Fatal("restoring cache extended rule expiry")
	}
	if e = a.writeSnapshotCache(s); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(cfg.SnapshotCacheFile)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe snapshot file permissions")
	}
	b := &App{cfg: cfg}
	if e = b.restoreSnapshotCache(); e != nil || b.active.Load() == nil || !b.cacheRestored.Load() {
		t.Fatal("valid cache not restored", e)
	}
	for name, test := range map[string]func() error{
		"expired": func() error { _, e := a.decodeSnapshot(sealed, now.Add(2*time.Hour)); return e },
		"other database": func() error {
			b := &App{cfg: cfg}
			b.cfg.DatabaseURL += "-other"
			_, e := b.decodeSnapshot(sealed, now)
			return e
		},
		"other key": func() error {
			b := &App{cfg: cfg}
			b.cfg.Key = make([]byte, 32)
			b.cfg.Key[0] = 1
			_, e := b.decodeSnapshot(sealed, now)
			return e
		},
		"tampered": func() error {
			copy := append([]byte{}, sealed...)
			copy[len(copy)-1] ^= 1
			_, e := a.decodeSnapshot(copy, now)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if test() == nil {
				t.Fatal("unsafe cache accepted")
			}
		})
	}
	prior, _ := os.ReadFile(cfg.SnapshotCacheFile)
	a.cfg.Key = []byte("bad")
	if e = a.writeSnapshotCache(s); e == nil {
		t.Fatal("invalid replacement succeeded")
	}
	after, _ := os.ReadFile(cfg.SnapshotCacheFile)
	if string(prior) != string(after) {
		t.Fatal("failed replacement damaged the old cache")
	}
}
func ptrInt64(v int64) *int64 { return &v }
func TestSnapshotCacheStartupBeforeDatabaseInitialization(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a := newTestReplica(t, cfg)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer up.Close()
	if _, e := a.db.Exec(context.Background(), "INSERT INTO sites(name,hostnames,upstream,enabled,redirect_https) VALUES('Cached app',ARRAY['offline.test'],$1,true,false)", up.URL); e != nil {
		t.Fatal(e)
	}
	if _, e := a.db.Exec(context.Background(), "UPDATE config_version SET version=version+1"); e != nil {
		t.Fatal(e)
	}
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	b.db.Close()
	if b.initialized.Load() || b.active.Load() == nil || !b.cacheRestored.Load() {
		t.Fatal("cache did not restore before database initialization")
	}
	w := httptest.NewRecorder()
	b.Public(w, httptest.NewRequest("GET", "http://offline.test/", nil))
	if w.Code != 202 {
		t.Fatal("cached proxy unavailable", w.Code)
	}
	w = httptest.NewRecorder()
	b.Management().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 {
		t.Fatal("cached replica unready", w.Code)
	}
	w = httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/sites", nil)
	request.AddCookie(&http.Cookie{Name: "aegis_waf_session", Value: "cannot-be-verified-offline"})
	b.Management().ServeHTTP(w, request)
	if w.Code != 503 {
		t.Fatal("offline management did not fail accurately", w.Code)
	}
	// Recovery switches back to database authority and discards the cache-restored marker.
	c, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = c.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if c.cacheRestored.Load() {
		t.Fatal("database recovery not reflected")
	}
	raw := httptest.NewRecorder()
	c.Management().ServeHTTP(raw, httptest.NewRequest("GET", "/readyz", nil))
	var ready map[string]bool
	json.Unmarshal(raw.Body.Bytes(), &ready)
	if !ready["ready"] {
		t.Fatal("recovered replica unready")
	}
}
