package app

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func managedPublicFixture(t *testing.T, upstreamURL string, overrides ...managedSignatureOptions) *App {
	t.Helper()
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	options := managedSignatureOptions{SetID: set.ID, Mode: "block"}
	if len(overrides) > 0 {
		options = overrides[0]
		options.SetID = set.ID
	}
	options, _ = normalizeManagedSignatures(options)
	runtime, e := compileManagedSignatures(set, options)
	if e != nil {
		t.Fatal(e)
	}
	target, _ := url.Parse(upstreamURL)
	policy, _ := compileProtection(defaultProtection())
	a := &App{managedSlots: make(chan struct{}, 64), access: make(chan accessEvent, 1024)}
	a.active.Store(&snapshot{routes: map[string]*route{"managed.test": {site: Site{ID: 1}, proxy: newProxy(target, true)}}, policyBindings: map[int64][]compiledPolicyBinding{1: {{ID: 1, Name: "Managed", Priority: 10000, Protection: policy, ManagedOptions: options, Managed: runtime}}}})
	return a
}
func TestManagedSignaturesPreserveStreamingAndHTTP2(t *testing.T) {
	unblock := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(unblock) }) }
	defer finish()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first\n")
		http.NewResponseController(w).Flush()
		select {
		case <-unblock:
		case <-r.Context().Done():
		}
		io.WriteString(w, "second\n")
	}))
	defer up.Close()
	a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: "block"})
	public := httptest.NewUnstartedServer(http.HandlerFunc(a.Public))
	chain, key := testCertificate(t, []string{"managed.test"}, 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	pair, e := tls.X509KeyPair([]byte(chain), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	public.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	public.EnableHTTP2 = true
	public.StartTLS()
	defer public.Close()
	client := public.Client()
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "managed.test"
	client.Timeout = 3 * time.Second
	r, _ := http.NewRequest("GET", public.URL+"/stream", nil)
	r.Host = "managed.test"
	r.Header.Set("User-Agent", "browser")
	r.Header.Set("Accept", "text/html")
	response, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ProtoMajor != 2 {
		t.Fatal("HTTP/2 forwarding failed", response.StatusCode, response.Proto)
	}
	first := make([]byte, 6)
	if _, e = io.ReadFull(response.Body, first); e != nil || string(first) != "first\n" {
		t.Fatal("stream was buffered", e)
	}
	if len(a.managedSlots) != 0 {
		t.Fatal("stream held an inspection slot")
	}
	finish()
	rest, e := io.ReadAll(response.Body)
	if e != nil || string(rest) != "second\n" {
		t.Fatal("stream bytes changed", e, string(rest))
	}
}
func TestManagedSignaturesPreserveWebSocketUpgrade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffer, e := http.NewResponseController(w).Hijack()
		if e != nil {
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		buffer.Flush()
		io.Copy(conn, conn)
	}))
	defer up.Close()
	a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: "block"})
	public := httptest.NewServer(http.HandlerFunc(a.Public))
	defer public.Close()
	target, _ := url.Parse(public.URL)
	connections := []net.Conn{}
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for n := 0; n < 65; n++ {
		conn, e := net.DialTimeout("tcp", target.Host, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		connections = append(connections, conn)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: managed.test\r\nUser-Agent: browser\r\nAccept: text/html\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		reader := bufio.NewReader(conn)
		response, e := http.ReadResponse(reader, nil)
		if e != nil || response.StatusCode != 101 {
			t.Fatal("upgrade rejected", n, e, response)
		}
		io.WriteString(conn, "ping")
		payload := make([]byte, 4)
		if _, e = io.ReadFull(reader, payload); e != nil || string(payload) != "ping" {
			t.Fatal("upgrade payload changed", e)
		}
	}
	if len(a.managedSlots) != 0 {
		t.Fatal("WebSocket lifetime held inspection reservations")
	}
}
func TestManagedBodyConcurrentCloseUnblocksRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	var once sync.Once
	released := make(chan struct{})
	body := &bufferedSignatureBody{prefix: bytes.NewReader([]byte("body")), original: reader, release: func() { once.Do(func() { close(released) }) }}
	prefix := make([]byte, 4)
	if _, e := io.ReadFull(body, prefix); e != nil || string(prefix) != "body" {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := body.Read(make([]byte, 1)); done <- e }()
	body.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock body Read")
	}
	select {
	case <-released:
	default:
		t.Fatal("body reservation not released")
	}
}
func TestManagedUnknownLengthObserveBody(t *testing.T) {
	set, _ := bundledSignatureSet()
	runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "observe", BodyLimit: 4096})
	if e != nil {
		t.Fatal(e)
	}
	a := &App{managedSlots: make(chan struct{}, 1)}
	payload := strings.Repeat("x", 8192)
	r := httptest.NewRequest("POST", "http://app.test/upload", io.NopCloser(strings.NewReader(payload)))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Header.Set("User-Agent", "browser")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Content-Type", "application/octet-stream")
	result, blocked, _ := a.inspectManaged(runtime, r, mustManagedIP())
	if blocked || result.Inspection != "partial" {
		t.Fatal("unknown-length capped Observe rejected", result)
	}
	body, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil || string(body) != payload || len(a.managedSlots) != 0 {
		t.Fatal("unknown-length body changed or reservation leaked", e)
	}
}
func mustManagedIP() netip.Addr { return netip.MustParseAddr("203.0.113.4") }
