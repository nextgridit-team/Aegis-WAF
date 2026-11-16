package app

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagementPlaintextNonLoopbackConfig(t *testing.T) {
	cases := []struct {
		name string
		addr string
		tls  bool
		want bool
	}{
		{"default wildcard bind", ":9090", false, true},
		{"all ipv4 interfaces", "0.0.0.0:9090", false, true},
		{"all ipv6 interfaces", "[::]:9090", false, true},
		{"lan address", "192.168.100.8:9090", false, true},
		{"hostname bind", "manage.example.test:9090", false, true},
		{"unparseable address", "9090", false, true},
		{"ipv4 loopback", "127.0.0.1:9090", false, false},
		{"ipv6 loopback", "[::1]:9090", false, false},
		{"localhost name", "localhost:9090", false, false},
		{"tls silences wildcard bind", ":9090", true, false},
		{"tls silences lan bind", "192.168.100.8:9090", true, false},
	}
	for _, tc := range cases {
		cfg := Config{ManagementAddr: tc.addr, ManagementTLS: tc.tls}
		if got := cfg.ManagementPlaintextNonLoopback(); got != tc.want {
			t.Fatalf("%s (addr %q tls %v): got %v want %v", tc.name, tc.addr, tc.tls, got, tc.want)
		}
	}
}
func TestStatusReportsManagementPlaintextNonLoopback(t *testing.T) {
	cfg := testDB(t)
	cfg.ManagementAddr = ":9090"
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	c := testAPI{t, client, server.URL, ""}
	credentials := map[string]string{"username": "plaintext-admin", "password": "strong plaintext management password", "secret": cfg.BootstrapSecret}
	c.call("POST", "/api/setup", credentials, 201)
	var login map[string]string
	c.call("POST", "/api/login", map[string]string{"username": "plaintext-admin", "password": credentials["password"]}, 200)
	json.Unmarshal(c.call("GET", "/api/me", nil, 200), &login)
	c.csrf = login["csrf"]
	status := func() map[string]any {
		var body map[string]any
		if e := json.Unmarshal(c.call("GET", "/api/status", nil, 200), &body); e != nil {
			t.Fatal(e)
		}
		return body
	}
	if body := status(); body["management_plaintext_non_loopback"] != true {
		t.Fatalf("status did not report plaintext non-loopback management bind: %v", body)
	}
	a.cfg.ManagementAddr = "127.0.0.1:9090"
	if body := status(); body["management_plaintext_non_loopback"] != false {
		t.Fatalf("status kept the warning for a loopback management bind: %v", body)
	}
	a.cfg.ManagementAddr = ":9090"
	a.cfg.ManagementTLS = true
	if body := status(); body["management_plaintext_non_loopback"] != false {
		t.Fatalf("status kept the warning after enabling management TLS: %v", body)
	}
}
