package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagementCertificateIndependentOfSites(t *testing.T) {
	now := time.Now()
	chain, key := testCertificate(t, []string{"*.example.test"}, 1, now.Add(-time.Hour), now.Add(time.Hour))
	pair, _, e := parseCertificate(chain, key, now)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	selectCert := a.ManagementTLSConfig().GetCertificate
	if _, e = selectCert(&tls.ClientHelloInfo{ServerName: "manage.example.test"}); e == nil {
		t.Fatal("TLS available before certificate snapshot")
	}
	a.active.Store(&snapshot{routes: map[string]*route{}, certificates: map[int64]*tls.Certificate{1: &pair}})
	if cert, e := selectCert(&tls.ClientHelloInfo{ServerName: "manage.example.test"}); e != nil || cert != &pair {
		t.Fatal("unassigned wildcard was not selected", e)
	}
	if _, e = selectCert(&tls.ClientHelloInfo{ServerName: "other.invalid"}); e == nil {
		t.Fatal("accepted uncovered management hostname")
	}
	if _, e = a.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "manage.example.test"}); e == nil {
		t.Fatal("management certificate exposed an unconfigured public route")
	}
	pair.Leaf.NotAfter = now.Add(-time.Second)
	if _, e = selectCert(&tls.ClientHelloInfo{ServerName: "manage.example.test"}); e == nil {
		t.Fatal("accepted expired management certificate")
	}
}
func TestManagementTLSLoginIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	bootstrap := httptest.NewServer(a.Management())
	defer bootstrap.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	c := testAPI{t, client, bootstrap.URL, ""}
	credentials := map[string]string{"username": "tls-admin", "password": "strong TLS management password", "secret": cfg.BootstrapSecret}
	c.call("POST", "/api/setup", credentials, 201)
	var login map[string]string
	c.call("POST", "/api/login", map[string]string{"username": "tls-admin", "password": credentials["password"]}, 200)
	json.Unmarshal(c.call("GET", "/api/me", nil, 200), &login)
	c.csrf = login["csrf"]
	now := time.Now()
	chain, key := testCertificate(t, []string{"*.example.test"}, 7, now.Add(-time.Hour), now.Add(time.Hour))
	c.call("POST", "/api/certificates", map[string]string{"name": "Management wildcard", "chain_pem": chain, "private_key_pem": key}, 200)
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
	}
	start := func(replica *App) *httptest.Server {
		server := httptest.NewUnstartedServer(replica.Management())
		server.TLS = replica.ManagementTLSConfig()
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	one, two := start(a), start(b)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(chain)) {
		t.Fatal("invalid test trust")
	}
	tlsJar, _ := cookiejar.New(nil)
	secure := &http.Client{Jar: tlsJar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "manage.example.test"}}}
	c = testAPI{t, secure, one.URL, ""}
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "tls-admin", "password": credentials["password"]}, 200), &login)
	c.csrf = login["csrf"]
	c.call("GET", "/api/me", nil, 200)
	other := testAPI{t, secure, two.URL, c.csrf}
	other.call("GET", "/api/me", nil, 200)
	other.call("POST", "/api/logout", map[string]any{}, 200)
	c.call("GET", "/api/me", nil, 401)
	// Loaded management TLS remains available without database reads per handshake.
	a.db.Close()
	if _, e := a.ManagementTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "manage.example.test"}); e != nil {
		t.Fatal("cached management TLS lost during database outage", e)
	}
}
func TestRemoteManagementCookieStaysSecure(t *testing.T) {
	r := httptest.NewRequest("GET", "http://192.168.100.8:9090/", nil)
	if !sessionCookie(r, "value", 60).Secure {
		t.Fatal("remote HTTP weakened session cookie")
	}
}
