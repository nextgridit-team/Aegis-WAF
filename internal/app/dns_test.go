package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCertificateDomainValidation(t *testing.T) {
	for _, tc := range []struct {
		hosts     []string
		challenge string
		ok        bool
	}{{[]string{"*.example.com", "example.com"}, "dns-01", true}, {[]string{"*.example.com"}, "http-01", false}, {[]string{"*.*.example.com"}, "dns-01", false}, {[]string{"example.com"}, "http-01", true}, {[]string{"*.127.0.0.1"}, "dns-01", false}} {
		_, e := certificateDomains(tc.hosts, tc.challenge)
		if (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}

type dnsTestTransport func(*http.Request) (*http.Response, error)

func (f dnsTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dnsTestProvider struct{ client *http.Client }

func (p dnsTestProvider) Present(host, token, response string) error {
	digest := sha256.Sum256([]byte(response))
	data, _ := json.Marshal(map[string]any{"type": "TXT", "name": "_acme-challenge." + host, "content": base64.RawURLEncoding.EncodeToString(digest[:])})
	r, e := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/zones/test-zone/dns_records", bytes.NewReader(data))
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 40))
	res, e := p.client.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("provider rejected")
	}
	return nil
}
func (p dnsTestProvider) CleanUp(string, string, string) error { return nil }
func TestDNSIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	c.call("GET", "/api/dns/credentials", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "dns-admin", "password": "dns integration password value", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "dns-admin", "password": "dns integration password value"}, 200), &login)
	c.csrf = login["csrf"]
	token := strings.Repeat("c", 40)
	credential := mustID(t, c.call("POST", "/api/dns/credentials", map[string]string{"name": "Cloudflare test", "api_token": token}, 200))
	var cipher []byte
	var keyID string
	if e := a.db.QueryRow(ctx, "SELECT token_cipher,key_id FROM dns_credentials WHERE id=$1", credential).Scan(&cipher, &keyID); e != nil {
		t.Fatal(e)
	}
	plain, e := open(cfg.Key, keyID+":dns-credential", cipher)
	if e != nil || string(plain) != token || bytes.Contains(cipher, []byte(token)) {
		t.Fatal("credential not encrypted correctly", e)
	}
	raw := c.call("GET", "/api/dns/credentials", nil, 200)
	if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte("cipher")) {
		t.Fatal("credential leaked")
	}
	c.call("PUT", fmt.Sprintf("/api/dns/credentials/%d", credential), map[string]string{"name": "Renamed", "api_token": ""}, 200)
	var unchanged []byte
	a.db.QueryRow(ctx, "SELECT token_cipher FROM dns_credentials WHERE id=$1", credential).Scan(&unchanged)
	if !bytes.Equal(unchanged, cipher) {
		t.Fatal("empty edit replaced token")
	}
	c.call("POST", "/api/dns/credentials", map[string]string{"name": "Invalid", "api_token": "Bearer private"}, 400)
	var mu sync.Mutex
	records := map[string]string{}
	var created atomic.Int64
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("incorrect Cloudflare authorization")
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			id := fmt.Sprintf("record-%d", created.Add(1))
			records[id] = body["content"]
			respond(w, 200, map[string]any{"success": true, "result": map[string]string{"id": id}})
			return
		}
		if r.Method == "DELETE" {
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			delete(records, id)
			respond(w, 200, map[string]any{"success": true})
			return
		}
		w.WriteHeader(404)
	}))
	defer cf.Close()
	base, _ := url.Parse(cf.URL)
	transport := dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Scheme = base.Scheme
		u.Host = base.Host
		clone.URL = &u
		return http.DefaultTransport.RoundTrip(clone)
	})
	for _, replica := range []*App{a, b} {
		replica.dnsTransport = transport
		replica.dnsFactory = func(ctx context.Context, token string, client *http.Client) (*cloudflareChallenge, error) {
			return &cloudflareChallenge{provider: dnsTestProvider{client}}, nil
		}
		replica.dnsWait = func(ctx context.Context, host, response string) error {
			digest := sha256.Sum256([]byte(response))
			want := base64.RawURLEncoding.EncodeToString(digest[:])
			mu.Lock()
			defer mu.Unlock()
			for _, v := range records {
				if v == want {
					return nil
				}
			}
			return fmt.Errorf("TXT value missing")
		}
	}
	ca := newTestCA(t)
	defer ca.server.Close()
	ca.dns = true
	ca.dnsValidate = func() bool { mu.Lock(); defer mu.Unlock(); return len(records) > 0 }
	oldTransport := http.DefaultTransport
	http.DefaultTransport = ca.server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	// The test transport above needs an independent plain HTTP transport to the fake API.
	a.dnsTransport = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Scheme = base.Scheme
		u.Host = base.Host
		clone.URL = &u
		return oldTransport.RoundTrip(clone)
	})
	b.dnsTransport = a.dnsTransport
	account := mustID(t, c.call("POST", "/api/acme/accounts", map[string]any{"directory": ca.server.URL + "/directory", "email": "dns@example.com", "accept_terms": true}, 201))
	c.call("POST", "/api/acme/certificates", map[string]any{"name": "Invalid wildcard", "domains": []string{"*.acme.example.com"}, "account_id": account}, 400)
	c.call("POST", "/api/acme/certificates", map[string]any{"name": "Missing credential", "domains": []string{"acme.example.com"}, "account_id": account, "challenge_type": "dns-01"}, 400)
	cert := mustID(t, c.call("POST", "/api/acme/certificates", map[string]any{"name": "Wildcard DNS certificate", "domains": []string{"*.acme.example.com"}, "account_id": account, "challenge_type": "dns-01", "dns_credential_id": credential}, 202))
	var wg sync.WaitGroup
	for _, replica := range []*App{a, b} {
		wg.Add(1)
		go func(app *App) { defer wg.Done(); app.runJobs(ctx) }(replica)
	}
	wg.Wait()
	var status, chain string
	if e = a.db.QueryRow(ctx, "SELECT j.status,c.chain_pem FROM jobs j JOIN certificates c ON c.id=j.certificate_id WHERE c.id=$1", cert).Scan(&status, &chain); e != nil || status != "succeeded" || !strings.Contains(chain, "BEGIN CERTIFICATE") {
		var message string
		a.db.QueryRow(ctx, "SELECT error FROM jobs WHERE certificate_id=$1", cert).Scan(&message)
		t.Fatal(status, e, message)
	}
	if ca.orders.Load() != 1 {
		t.Fatal("competing replicas issued multiple orders")
	}
	var pending int
	a.db.QueryRow(ctx, "SELECT count(*) FROM dns_challenges").Scan(&pending)
	mu.Lock()
	left := len(records)
	mu.Unlock()
	if pending != 0 || left != 0 {
		t.Fatal("TXT cleanup incomplete", pending, left)
	}
	c.call("DELETE", fmt.Sprintf("/api/dns/credentials/%d", credential), nil, 409)
	// Another replica can recover a persisted record after the presenting replica exits.
	var job int64
	a.db.QueryRow(ctx, "SELECT id FROM jobs WHERE certificate_id=$1", cert).Scan(&job)
	mu.Lock()
	records["abandoned"] = "old"
	mu.Unlock()
	if _, e = a.db.Exec(ctx, "INSERT INTO dns_challenges(job_id,credential_id,zone_id,record_id) VALUES($1,$2,'test-zone','abandoned')", job, credential); e != nil {
		t.Fatal(e)
	}
	if e = b.cleanupDNSRecords(ctx, job, false); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	left = len(records)
	mu.Unlock()
	if left != 0 {
		t.Fatal("abandoned TXT not cleaned")
	}
	// Failed renewal keeps the working certificate and displays a retry state.
	ca.fail.Store(true)
	renewal := mustID(t, c.call("POST", fmt.Sprintf("/api/certificates/%d/renew", cert), map[string]any{}, 202))
	c.call("POST", fmt.Sprintf("/api/certificates/%d/renew", cert), map[string]any{}, 409)
	a.runJobs(ctx)
	var kept string
	a.db.QueryRow(ctx, "SELECT chain_pem FROM certificates WHERE id=$1", cert).Scan(&kept)
	if kept != chain {
		t.Fatal("failed renewal replaced working certificate")
	}
	var retries int
	a.db.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE certificate_id=$1 AND status='retry'", cert).Scan(&retries)
	if retries != 1 {
		t.Fatal("renewal failure not visible")
	}
	ca.fail.Store(false)
	c.call("POST", fmt.Sprintf("/api/acme/jobs/%d/retry", renewal), map[string]any{}, 202)
	b.runJobs(ctx)
	var replacement string
	if e = a.db.QueryRow(ctx, "SELECT chain_pem FROM certificates WHERE id=$1", cert).Scan(&replacement); e != nil {
		t.Fatal(e)
	}
	before, _ := pemLeaf(chain)
	after, _ := pemLeaf(replacement)
	if before == nil || after == nil {
		t.Fatal("missing renewed certificate")
	}
	beforeKey, _ := x509.MarshalPKIXPublicKey(before.PublicKey)
	afterKey, _ := x509.MarshalPKIXPublicKey(after.PublicKey)
	if bytes.Equal(beforeKey, afterKey) {
		t.Fatal("manual DNS renewal did not rotate certificate key")
	}

}
