package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

func TestAddressValues(t *testing.T) {
	for raw, want := range map[string]string{"192.168.1.12": "192.168.1.12", "192.168.1.12/24": "192.168.1.0/24", "192.168.1.12/255.255.255.0": "192.168.1.0/24", "192.168.1.12 255.255.255.0": "192.168.1.0/24", "2001:db8::123/64": "2001:db8::/64", "::ffff:192.168.1.1": "192.168.1.1"} {
		got, e := normalizeAddressValue(raw)
		if e != nil || got != want {
			t.Fatalf("%s: %s %v", raw, got, e)
		}
	}
	for _, raw := range []string{"1.2.3.4,5.6.7.8", "example.com", "192.168.0.0/255.0.255.0", "0.0.0.0/0", "::/0", "fe80::1%eth0", "192.168.1.0 0.0.0.0"} {
		if _, e := normalizeAddressValue(raw); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestAddressObjectsIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	c.call("GET", "/api/address-objects", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "address objects test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "address objects test password"}, 200), &login)
	c.csrf = login["csrf"]
	obj := mustID(t, c.call("POST", "/api/address-objects", map[string]any{"name": "F5", "value": "192.0.2.1"}, 200))
	group := mustID(t, c.call("POST", "/api/address-groups", map[string]any{"name": "Trusted edge", "object_ids": []int64{obj}}, 200))
	c.call("POST", "/api/address-objects", map[string]any{"name": "f5", "value": "192.0.2.2"}, 409)
	c.call("POST", "/api/address-groups", map[string]any{"name": "missing", "object_ids": []int64{99999}}, 409)
	p := defaultProtection()
	p.TrustedAddresses = addressSelection{GroupIDs: []int64{group}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer upstream.Close()
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Objects", "hostnames": []string{"objects.test"}, "upstream": upstream.URL, "enabled": true, "protection": p}, 200))
	check := func(want string) {
		t.Helper()
		for _, replica := range []*App{a, b} {
			if e := replica.refresh(context.Background()); e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest("GET", "http://objects.test/", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("X-Forwarded-For", "198.51.100.2")
			got := replica.active.Load().protection[site].clientIP(r).String()
			if got != want {
				t.Fatalf("identity %s, want %s", got, want)
			}
		}
	}
	check("198.51.100.2")
	c.call("DELETE", fmt.Sprintf("/api/address-objects/%d", obj), nil, 409)
	c.call("DELETE", fmt.Sprintf("/api/address-groups/%d", group), nil, 409)
	c.call("PUT", fmt.Sprintf("/api/address-objects/%d", obj), map[string]any{"name": "F5", "value": "192.0.2.2"}, 200)
	check("192.0.2.1")
	// Invalid references cannot replace the last working configuration.
	p.TrustedAddresses.GroupIDs = []int64{99999}
	c.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 409)
	check("192.0.2.1")
	p.TrustedAddresses = addressSelection{}
	c.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
	c.call("DELETE", fmt.Sprintf("/api/address-groups/%d", group), nil, 200)
	c.call("DELETE", fmt.Sprintf("/api/address-objects/%d", obj), nil, 200)
}
