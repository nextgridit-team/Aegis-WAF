package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type testAPI struct {
	t          *testing.T
	client     *http.Client
	base, csrf string
}

func (c *testAPI) call(method, path string, body any, want int) []byte {
	c.t.Helper()
	b, _ := json.Marshal(body)
	r, e := http.NewRequest(method, c.base+path, bytes.NewReader(b))
	if e != nil {
		c.t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "aegis-waf")
	r.Header.Set("X-CSRF-Token", c.csrf)
	res, e := c.client.Do(r)
	if e != nil {
		c.t.Fatal(e)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		c.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.StatusCode, want, data)
	}
	return data
}
func testDB(t *testing.T) Config {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("set TEST_DATABASE_URL to run real PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	schemaName := fmt.Sprintf("test_%d", time.Now().UnixNano())
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schemaName); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { admin.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE"); admin.Close() })
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schemaName)
	u.RawQuery = q.Encode()
	return Config{DatabaseURL: u.String(), BootstrapSecret: strings.Repeat("b", 40), Key: bytes.Repeat([]byte{1}, 32), KeyID: "test", Refresh: 25 * time.Millisecond}
}
func newTestReplica(t *testing.T, cfg Config) *App {
	t.Helper()
	a, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	a.dbOK.Store(true)
	t.Cleanup(a.Close)
	return a
}
func mustID(t *testing.T, data []byte) int64 {
	t.Helper()
	var v struct {
		ID int64 `json:"id"`
	}
	if e := json.Unmarshal(data, &v); e != nil || v.ID == 0 {
		t.Fatalf("missing id: %s", data)
	}
	return v.ID
}
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition did not converge")
}
func TestIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	s1, s2 := httptest.NewServer(a.Management()), httptest.NewServer(b.Management())
	defer s1.Close()
	defer s2.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	c := testAPI{t, client, s1.URL, ""}
	other := testAPI{t, client, s2.URL, ""}
	password := "correct horse battery gateway"
	t.Run("bootstrap sessions and CSRF", func(t *testing.T) {
		c.t = t
		other.t = t
		c.call("GET", "/api/me", nil, 401)
		c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": password, "secret": "incorrect"}, 403)
		c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": password, "secret": cfg.BootstrapSecret}, 201)
		c.call("POST", "/api/setup", map[string]string{"username": "other", "password": password, "secret": cfg.BootstrapSecret}, 409)
		data := c.call("POST", "/api/login", map[string]string{"username": "admin", "password": password}, 200)
		var login map[string]string
		json.Unmarshal(data, &login)
		c.csrf = login["csrf"]
		other.csrf = c.csrf
		other.call("GET", "/api/me", nil, 200)
		saved := c.csrf
		c.csrf = "bad"
		c.call("POST", "/api/sites", map[string]any{}, 403)
		c.csrf = saved
		r, _ := http.NewRequest("POST", s1.URL+"/api/logout", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Requested-With", "aegis-waf")
		r.Header.Set("X-CSRF-Token", saved)
		r.Header.Set("Origin", "https://evil.example")
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatal("accepted cross-origin mutation")
		}
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		io.WriteString(w, "application response")
	}))
	defer upstream.Close()
	now := time.Now()
	chain, key := testCertificate(t, []string{"app.example.com"}, 100, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	var certID, siteID int64
	t.Run("upload attach encryption and shared snapshots", func(t *testing.T) {
		c.t = t
		other.t = t
		certID = mustID(t, c.call("POST", "/api/certificates", map[string]string{"name": "Application TLS", "chain_pem": chain, "private_key_pem": key}, 200))
		var encrypted []byte
		if e := a.db.QueryRow(ctx, "SELECT key_cipher FROM certificates WHERE id=$1", certID).Scan(&encrypted); e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(encrypted, []byte("PRIVATE KEY")) || bytes.Equal(encrypted, []byte(key)) {
			t.Fatal("private key stored as plaintext")
		}
		body := map[string]any{"name": "Application", "hostnames": []string{"app.example.com"}, "upstream": upstream.URL, "certificate_id": certID, "redirect_https": true, "preserve_host": true, "enabled": true}
		siteID = mustID(t, c.call("POST", "/api/sites", body, 200))
		body["name"] = "Duplicate"
		c.call("POST", "/api/sites", body, 409)
		body["hostnames"] = []string{"other.example.com"}
		c.call("POST", "/api/sites", body, 400)
		for _, replica := range []*App{a, b} {
			if e := replica.refresh(ctx); e != nil {
				t.Fatal(e)
			}
			pair, e := replica.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
			if e != nil || pair.Leaf.SerialNumber.Int64() != 100 {
				t.Fatal(e)
			}
			r := httptest.NewRequest("GET", "http://app.example.com/safe", nil)
			w := httptest.NewRecorder()
			replica.Public(w, r)
			if w.Code != 308 || w.Header().Get("Location") != "https://app.example.com/safe" {
				t.Fatalf("redirect: %d %v", w.Code, w.Header())
			}
		}
		read := other.call("GET", "/api/certificates", nil, 200)
		if bytes.Contains(read, []byte("PRIVATE KEY")) || bytes.Contains(read, []byte("key_cipher")) {
			t.Fatal("key exposed")
		}
		if !bytes.Contains(read, []byte("Application TLS")) || !bytes.Contains(read, []byte("assigned_sites")) {
			t.Fatal(string(read))
		}
	})
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(b.Public))
	tlsServer.TLS = b.TLSConfig()
	tlsServer.StartTLS()
	defer tlsServer.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.com"}}
	defer transport.CloseIdleConnections()
	httpsClient := &http.Client{Transport: transport}
	getTLS := func(t *testing.T, want int64) {
		t.Helper()
		transport.CloseIdleConnections()
		r, _ := http.NewRequest("GET", tlsServer.URL+"/", nil)
		r.Host = "app.example.com"
		res, e := httpsClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 202 || string(data) != "application response" || res.TLS.PeerCertificates[0].SerialNumber.Int64() != want {
			t.Fatalf("unexpected proxied TLS response: %d %s", res.StatusCode, data)
		}
	}
	t.Run("live TLS replacement rollback and propagation", func(t *testing.T) {
		c.t = t
		getTLS(t, 100)
		wrong, wkey := testCertificate(t, []string{"wrong.example.com"}, 101, now.Add(-time.Hour), now.Add(time.Hour))
		c.call("PUT", fmt.Sprintf("/api/certificates/%d", certID), map[string]string{"name": "wrong", "chain_pem": wrong, "private_key_pem": wkey}, 400)
		getTLS(t, 100)
		replacement, rkey := testCertificate(t, []string{"app.example.com"}, 102, now.Add(-time.Hour), now.Add(90*24*time.Hour))
		_, e := a.db.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT test_failure CHECK(action<>'certificate.replaced')")
		if e != nil {
			t.Fatal(e)
		}
		c.call("PUT", fmt.Sprintf("/api/certificates/%d", certID), map[string]string{"name": "replace", "chain_pem": replacement, "private_key_pem": rkey}, 503)
		if _, e = a.db.Exec(ctx, "ALTER TABLE audit_events DROP CONSTRAINT test_failure"); e != nil {
			t.Fatal(e)
		}
		if e = b.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		getTLS(t, 100)
		c.call("PUT", fmt.Sprintf("/api/certificates/%d", certID), map[string]string{"name": "replace", "chain_pem": replacement, "private_key_pem": rkey}, 200)
		pollCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); b.Background(pollCtx) }()
		eventually(t, func() bool {
			s := b.active.Load()
			return s.routes["app.example.com"].cert.Leaf.SerialNumber.Int64() == 102
		})
		cancel()
		<-done
		getTLS(t, 102)
		c.call("DELETE", fmt.Sprintf("/api/certificates/%d", certID), nil, 409)
	})
	t.Run("ACME shared challenges coordinated issuance retry and renewal", func(t *testing.T) {
		c.t = t
		ca := newTestCA(t, a, b)
		defer ca.server.Close()
		old := http.DefaultTransport
		http.DefaultTransport = ca.server.Client().Transport
		defer func() { http.DefaultTransport = old }()
		c.call("GET", "/api/acme/directory?url="+url.QueryEscape(ca.server.URL+"/directory"), nil, 200)
		c.call("POST", "/api/acme/accounts", map[string]any{"directory": ca.server.URL + "/directory", "email": "admin@example.com", "accept_terms": false}, 400)
		account := mustID(t, c.call("POST", "/api/acme/accounts", map[string]any{"directory": ca.server.URL + "/directory", "email": "admin@example.com", "accept_terms": true}, 201))
		acmeCert := mustID(t, c.call("POST", "/api/acme/certificates", map[string]any{"name": "ACME application", "domains": []string{"acme.example.com"}, "account_id": account}, 202))
		var job int64
		if e := a.db.QueryRow(ctx, "SELECT id FROM jobs WHERE certificate_id=$1", acmeCert).Scan(&job); e != nil {
			t.Fatal(e)
		}
		var wg sync.WaitGroup
		for _, replica := range []*App{a, b} {
			wg.Add(1)
			go func(replica *App) { defer wg.Done(); replica.runJob(ctx, job, acmeCert) }(replica)
		}
		wg.Wait()
		var jobStatus, msg string
		if e := a.db.QueryRow(ctx, "SELECT status,error FROM jobs WHERE id=$1", job).Scan(&jobStatus, &msg); e != nil {
			t.Fatal(e)
		}
		if jobStatus != "succeeded" {
			t.Fatalf("issuance status=%s error=%s", jobStatus, msg)
		}
		if ca.orders.Load() != 1 || ca.challenges.Load() != 2 {
			t.Fatalf("orders %d, replica challenges %d", ca.orders.Load(), ca.challenges.Load())
		}
		var oldChain string
		a.db.QueryRow(ctx, "SELECT chain_pem FROM certificates WHERE id=$1", acmeCert).Scan(&oldChain)
		ca.fail.Store(true)
		// Force renewal eligibility without changing the cached or stored certificate material.
		if _, e := a.db.Exec(ctx, "UPDATE certificates SET not_before=now()-interval '60 days',not_after=now()+interval '1 day' WHERE id=$1", acmeCert); e != nil {
			t.Fatal(e)
		}
		a.schedule(ctx)
		a.schedule(ctx)
		var renewal int64
		if e := a.db.QueryRow(ctx, "SELECT id FROM jobs WHERE certificate_id=$1 AND status='queued'", acmeCert).Scan(&renewal); e != nil {
			t.Fatal(e)
		}
		a.runJob(ctx, renewal, acmeCert)
		var kept string
		a.db.QueryRow(ctx, "SELECT chain_pem FROM certificates WHERE id=$1", acmeCert).Scan(&kept)
		a.db.QueryRow(ctx, "SELECT status,error FROM jobs WHERE id=$1", renewal).Scan(&jobStatus, &msg)
		if kept != oldChain || jobStatus != "retry" || msg == "" {
			t.Fatalf("failed renewal did not preserve certificate: %s %s", jobStatus, msg)
		}
		var next time.Time
		a.db.QueryRow(ctx, "SELECT next_attempt FROM jobs WHERE id=$1", renewal).Scan(&next)
		if !next.After(time.Now()) {
			t.Fatal("missing retry backoff")
		}
		ca.fail.Store(false)
		c.call("POST", fmt.Sprintf("/api/acme/jobs/%d/retry", renewal), map[string]any{}, 202)
		b.runJob(ctx, renewal, acmeCert)
		a.db.QueryRow(ctx, "SELECT status,error FROM jobs WHERE id=$1", renewal).Scan(&jobStatus, &msg)
		if jobStatus != "succeeded" {
			t.Fatalf("retry did not succeed: %s", msg)
		}
		// A stale 'running' job whose connection died must be recovered by another replica.
		if _, e := a.db.Exec(ctx, "UPDATE certificates SET not_before=now()-interval '60 days',not_after=now()+interval '1 day' WHERE id=$1", acmeCert); e != nil {
			t.Fatal(e)
		}
		a.schedule(ctx)
		var orphan int64
		a.db.QueryRow(ctx, "SELECT id FROM jobs WHERE certificate_id=$1 AND status='queued'", acmeCert).Scan(&orphan)
		a.db.Exec(ctx, "UPDATE jobs SET status='running',owner='dead-replica' WHERE id=$1", orphan)
		b.runJob(ctx, orphan, acmeCert)
		a.db.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", orphan).Scan(&jobStatus)
		if jobStatus != "succeeded" {
			t.Fatal("orphaned job not recovered")
		}
	})
	t.Run("audit access log persistence and session revocation", func(t *testing.T) {
		c.t = t
		other.t = t
		data := c.call("GET", "/api/audit", nil, 200)
		for _, action := range []string{"certificate.uploaded", "certificate.replaced", "site.saved", "acme.certificate.issued"} {
			if !bytes.Contains(data, []byte(action)) {
				t.Fatal("missing audit: " + action)
			}
		}
		if bytes.Contains(data, []byte(password)) || bytes.Contains(data, []byte(key)) {
			t.Fatal("secret in audit")
		}
		logCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); b.logWorker(logCtx) }()
		eventually(t, func() bool {
			var n int
			a.db.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE site_id=$1", siteID).Scan(&n)
			return n > 0
		})
		cancel()
		<-done
		c.call("POST", "/api/logout", map[string]any{}, 200)
		other.call("GET", "/api/me", nil, 401)
		data = c.call("POST", "/api/login", map[string]string{"username": "admin", "password": password}, 200)
		var login map[string]string
		json.Unmarshal(data, &login)
		c.csrf = login["csrf"]
	})
	t.Run("database failure retains last working proxy and refuses administration", func(t *testing.T) {
		c.t = t
		a.db.Close()
		b.db.Close()
		if e := b.refresh(ctx); e == nil {
			t.Fatal("database failure not reported")
		}
		getTLS(t, 102)
		c.call("POST", "/api/sites", map[string]any{}, 503)
		c.call("GET", "/readyz", nil, 200)
	})
}

// testCA implements a local RFC 8555 interaction fixture. It exercises the real
// x/crypto/acme client; it is not used by the application or shipped as a service.
type testCA struct {
	server                *httptest.Server
	orders, challenges    atomic.Int64
	fail                  atomic.Bool
	mu                    sync.Mutex
	authorized, finalized bool
	hosts                 []string
	chain                 string
	replicas              []*App
	t                     *testing.T
}

func newTestCA(t *testing.T, replicas ...*App) *testCA {
	ca := &testCA{t: t, replicas: replicas}
	ca.server = httptest.NewTLSServer(http.HandlerFunc(ca.serve))
	return ca
}
func (ca *testCA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	w.Header().Set("Replay-Nonce", token())
	w.Header().Set("Content-Type", "application/json")
	base := ca.server.URL
	decodePayload := func(v any) {
		var envelope struct {
			Payload string `json:"payload"`
		}
		json.NewDecoder(r.Body).Decode(&envelope)
		body, _ := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if e := json.Unmarshal(body, v); e != nil {
			ca.t.Errorf("ACME payload: %v", e)
		}
	}
	order := func() map[string]any {
		state := "pending"
		if ca.authorized {
			state = "ready"
		}
		if ca.finalized {
			state = "valid"
		}
		return map[string]any{"status": state, "identifiers": []map[string]string{{"type": "dns", "value": "acme.example.com"}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1", "certificate": base + "/certificate/1"}
	}
	switch r.URL.Path {
	case "/directory":
		respond(w, 200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order", "meta": map[string]string{"termsOfService": base + "/terms"}})
	case "/nonce":
		w.WriteHeader(200)
	case "/account":
		w.Header().Set("Location", base+"/account/1")
		respond(w, 201, map[string]any{"status": "valid", "contact": []string{"mailto:admin@example.com"}, "orders": base + "/orders"})
	case "/new-order":
		if ca.fail.Load() {
			respond(w, 400, map[string]any{"type": "urn:ietf:params:acme:error:rejectedIdentifier", "detail": "temporary test failure", "status": 400})
			return
		}
		var body struct {
			Identifiers []struct {
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		decodePayload(&body)
		ca.hosts = nil
		for _, id := range body.Identifiers {
			ca.hosts = append(ca.hosts, id.Value)
		}
		ca.authorized = false
		ca.finalized = false
		ca.orders.Add(1)
		w.Header().Set("Location", base+"/order/1")
		respond(w, 201, order())
	case "/order/1":
		respond(w, 200, order())
	case "/authz/1":
		state := "pending"
		if ca.authorized {
			state = "valid"
		}
		respond(w, 200, map[string]any{"status": state, "identifier": map[string]string{"type": "dns", "value": "acme.example.com"}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge/1", "status": state, "token": "shared-challenge-token"}}})
	case "/challenge/1":
		for _, a := range ca.replicas {
			r := httptest.NewRequest("GET", "http://acme.example.com/.well-known/acme-challenge/shared-challenge-token", nil)
			rec := httptest.NewRecorder()
			a.Public(rec, r)
			if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "shared-challenge-token.") {
				ca.t.Errorf("challenge unavailable on replica: %d %s", rec.Code, rec.Body.String())
			}
			ca.challenges.Add(1)
		}
		ca.authorized = true
		respond(w, 200, map[string]string{"type": "http-01", "url": base + "/challenge/1", "status": "valid", "token": "shared-challenge-token"})
	case "/finalize/1":
		var body struct {
			CSR string `json:"csr"`
		}
		decodePayload(&body)
		der, _ := base64.RawURLEncoding.DecodeString(body.CSR)
		csr, e := x509.ParseCertificateRequest(der)
		if e != nil {
			ca.t.Error(e)
			w.WriteHeader(400)
			return
		}
		if e = csr.CheckSignature(); e != nil {
			ca.t.Error(e)
		}
		issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		now := time.Now()
		issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		rootDER, _ := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(ca.orders.Load() + 200), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		leafDER, e := x509.CreateCertificate(rand.Reader, leaf, issuer, csr.PublicKey, issuerKey)
		if e != nil {
			ca.t.Error(e)
		}
		ca.chain = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
		ca.finalized = true
		respond(w, 200, order())
	case "/certificate/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		io.WriteString(w, ca.chain)
	default:
		http.NotFound(w, r)
	}
}

func TestConcurrentBootstrap(t *testing.T) {
	cfg := testDB(t)
	ctx := context.Background()
	a, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	errs := make(chan error, 2)
	for _, replica := range []*App{a, b} {
		go func(replica *App) { errs <- replica.initialize(ctx) }(replica)
	}
	for range 2 {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	left, right := httptest.NewServer(a.Management()), httptest.NewServer(b.Management())
	defer left.Close()
	defer right.Close()
	codes := make(chan int, 2)
	for index, base := range []string{left.URL, right.URL} {
		go func(index int, base string) {
			body, _ := json.Marshal(map[string]string{"username": fmt.Sprintf("admin-%d", index), "password": "a unique bootstrap test password", "secret": cfg.BootstrapSecret})
			req, _ := http.NewRequest("POST", base+"/api/setup", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "aegis-waf")
			res, e := http.DefaultClient.Do(req)
			if e != nil {
				codes <- 0
				return
			}
			defer res.Body.Close()
			codes <- res.StatusCode
		}(index, base)
	}
	one, two := <-codes, <-codes
	if !((one == 201 && two == 409) || (one == 409 && two == 201)) {
		t.Fatalf("bootstrap race returned %d and %d", one, two)
	}
	var count int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM administrators").Scan(&count); e != nil || count != 1 {
		t.Fatalf("admin count=%d: %v", count, e)
	}
}
