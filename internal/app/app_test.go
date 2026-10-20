package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T, hosts []string, serial int64, from, to time.Time) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts, NotBefore: from, NotAfter: to, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}
func TestCertificateValidation(t *testing.T) {
	now := time.Now()
	chain, key := testCertificate(t, []string{"app.example.com", "*.example.net"}, 1, now.Add(-time.Hour), now.Add(time.Hour))
	_, leaf, e := parseCertificate(chain, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = covers(leaf, []string{"app.example.com", "one.example.net"}); e != nil {
		t.Fatal(e)
	}
	if covers(leaf, []string{"other.example.com"}) == nil {
		t.Fatal("accepted uncovered hostname")
	}
	_, other := testCertificate(t, []string{"app.example.com"}, 2, now.Add(-time.Hour), now.Add(time.Hour))
	for name, k := range map[string]string{"mismatch": other, "malformed": "no key", "extra PEM": key + key} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := parseCertificate(chain, k, now); e == nil {
				t.Fatal("accepted invalid key")
			}
		})
	}
	for _, n := range []time.Time{now.Add(-2 * time.Hour), now.Add(2 * time.Hour)} {
		if _, _, e := parseCertificate(chain, key, n); e == nil {
			t.Fatal("accepted invalid validity")
		}
	}
}
func TestAuthenticatedEncryption(t *testing.T) {
	key := make([]byte, 32)
	enc, e := seal(key, "primary:certificate", []byte("secret key"))
	if e != nil {
		t.Fatal(e)
	}
	plain, e := open(key, "primary:certificate", enc)
	if e != nil || string(plain) != "secret key" {
		t.Fatal(e)
	}
	if _, e = open(key, "other:certificate", enc); e == nil {
		t.Fatal("accepted wrong key identifier")
	}
	enc[len(enc)-1] ^= 1
	if _, e = open(key, "primary:certificate", enc); e == nil {
		t.Fatal("accepted tampered ciphertext")
	}
}
func TestProxyTrustAndStreaming(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "192.0.2.10" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "app.example.com" || r.Header.Get("X-Forwarded-Proto") != "http" {
			t.Errorf("unexpected forwarded headers: %v", r.Header)
		}
		if r.Host != "app.example.com" {
			t.Error("host not preserved")
		}
		w.WriteHeader(201)
		io.WriteString(w, "first\n")
		http.NewResponseController(w).Flush()
		io.WriteString(w, "second\n")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	a := &App{access: make(chan accessEvent, 10)}
	a.active.Store(&snapshot{version: 1, routes: map[string]*route{"app.example.com": {site: Site{ID: 1}, proxy: newProxy(u, true)}}})
	r := httptest.NewRequest("GET", "http://app.example.com/path?secret=omit", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Forwarded-For", "trusted-admin")
	r.Header.Set("Forwarded", "for=spoof")
	r.Header.Set("X-Forwarded-Host", "spoof")
	w := httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != 201 || w.Body.String() != "first\nsecond\n" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	event := <-a.access
	if event.status != 201 || event.peer != "192.0.2.10" {
		t.Fatal(event)
	}
	r.Host = "unknown.example.com"
	w = httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != 421 {
		t.Fatal(w.Code)
	}
}
func TestTLSRequiresConfiguredSNICurrentCertificate(t *testing.T) {
	now := time.Now()
	chain, key := testCertificate(t, []string{"app.example.com"}, 1, now.Add(-time.Hour), now.Add(time.Hour))
	pair, _, _ := parseCertificate(chain, key, now)
	a := &App{}
	a.active.Store(&snapshot{routes: map[string]*route{"app.example.com": {cert: &pair}}})
	selectCert := a.TLSConfig().GetCertificate
	if _, e := selectCert(&tls.ClientHelloInfo{ServerName: "app.example.com"}); e != nil {
		t.Fatal(e)
	}
	if _, e := selectCert(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); e == nil {
		t.Fatal("accepted unknown SNI")
	}
	pair.Leaf.NotAfter = now.Add(-time.Minute)
	if _, e := selectCert(&tls.ClientHelloInfo{ServerName: "app.example.com"}); e == nil {
		t.Fatal("accepted expired certificate")
	}
}
func TestHostAndUpstreamValidation(t *testing.T) {
	for _, h := range []string{"a", "*.example.com", "a..example.com", "127.0.0.1", "a.example.com:443", "-a.example.com", "a.example.com\r\nfoo"} {
		if _, e := hostname(h); e == nil {
			t.Errorf("accepted %q", h)
		}
	}
	h, e := hostname("APP.Example.COM.")
	if e != nil || h != "app.example.com" {
		t.Fatal(h, e)
	}
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com", "http://example.com?secret=value"} {
		if validateUpstream(u) == nil {
			t.Errorf("accepted %q", u)
		}
	}
}
func TestOriginAndUnauthenticatedCSRF(t *testing.T) {
	a := &App{}
	handler := a.wrap(false, func(w http.ResponseWriter, r *http.Request, _ identity) error { return nil })
	for _, origin := range []string{"https://evil.example", "null"} {
		r := httptest.NewRequest("POST", "http://localhost/api/login", strings.NewReader("{}"))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Requested-With", "aegis-waf")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q accepted", origin)
		}
	}
	r := httptest.NewRequest("POST", "http://localhost/api/login", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != 403 {
		t.Fatal("missing request header accepted")
	}
}
func TestNewReplicaUnreadyWithoutDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{DatabaseURL: "postgres://aegis_waf@127.0.0.1:1/aegis-waf?sslmode=disable", Refresh: 10 * time.Millisecond}
	a, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); a.Background(ctx) }()
	w := httptest.NewRecorder()
	a.Management().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatal("new disconnected replica ready")
	}
	cancel()
	<-done
	a.Close()
}

func TestProxyProtocolUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffer, e := http.NewResponseController(w).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer conn.Close()
		fmt.Fprint(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buffer.Flush()
		line, e := buffer.ReadString('\n')
		if e != nil {
			t.Error(e)
			return
		}
		fmt.Fprint(buffer, line)
		buffer.Flush()
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	a := &App{access: make(chan accessEvent, 1)}
	a.active.Store(&snapshot{routes: map[string]*route{"app.example.com": {site: Site{ID: 1}, proxy: newProxy(u, true)}}})
	front := httptest.NewServer(http.HandlerFunc(a.Public))
	defer front.Close()
	conn, e := net.DialTimeout("tcp", strings.TrimPrefix(front.URL, "http://"), 2*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "GET /socket HTTP/1.1\r\nHost: app.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, e := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if e != nil {
		t.Fatal(e)
	}
	if response.StatusCode != 101 {
		t.Fatal(response.StatusCode)
	}
	fmt.Fprint(conn, "upgrade payload\n")
	line, e := reader.ReadString('\n')
	if e != nil || line != "upgrade payload\n" {
		t.Fatalf("upgrade echo: %q %v", line, e)
	}
	conn.Close()
	select {
	case log := <-a.access:
		if log.status != 101 {
			t.Fatalf("upgrade logged %d", log.status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upgrade did not finish")
	}
}

func TestProxyRejectsUntrustedUpstreamTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "must not be reached") }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	proxy := newProxy(u, true)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://app.example.com", nil))
	if w.Code != 502 {
		t.Fatalf("untrusted upstream TLS accepted: %d", w.Code)
	}
}
