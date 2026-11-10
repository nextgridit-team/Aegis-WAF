package app

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestApplicationAccessValidation(t *testing.T) {
	oidc := identityProviderSettings{Name: "Company", Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://login.example.test/tenant/v2.0", ClientID: "app"}}
	got, e := normalizeIdentityProvider(oidc)
	if e != nil || got.OIDC.GroupsClaim != "groups" || len(got.OIDC.Scopes) != 3 {
		t.Fatal(got, e)
	}
	directory := identityProviderSettings{Name: "Directory", Type: "ldap", Enabled: true, LDAP: &ldapSettings{URL: "ldaps://directory.example.test:636", BindDN: "cn=reader,dc=example,dc=test", UserBaseDN: "ou=people,dc=example,dc=test"}}
	if _, e := normalizeIdentityProvider(directory); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"http://login.example.test", "https://user:pass@login.example.test", "https://login.example.test?x=1", "https://login.example.test#fragment"} {
		bad := oidc
		config := *oidc.OIDC
		config.Issuer = raw
		bad.OIDC = &config
		if _, e := normalizeIdentityProvider(bad); e == nil {
			t.Fatal("accepted unsafe issuer", raw)
		}
	}
	for _, raw := range []string{"ldap://host/dc=example", "http://host", "ldaps://user:pass@host"} {
		bad := directory
		config := *directory.LDAP
		config.URL = raw
		bad.LDAP = &config
		if _, e := normalizeIdentityProvider(bad); e == nil {
			t.Fatal("accepted unsafe LDAP URL", raw)
		}
	}
	restricted := applicationAccessSettings{Enabled: true, ProviderID: 1, PublicOrigin: "https://app.example.test", AllowedGroups: []string{"finance"}}
	if _, e := normalizeApplicationAccess(restricted); e != nil {
		t.Fatal(e)
	}
	withPort := restricted
	withPort.PublicOrigin = "https://APP.EXAMPLE.TEST:443/"
	if normalized, err := normalizeApplicationAccess(withPort); err != nil || normalized.PublicOrigin != "https://app.example.test" {
		t.Fatal("default HTTPS port would cause canonical redirect loops", normalized, err)
	}
	if identityAllowed(restricted, applicationIdentity{Subject: "user", Groups: []string{"Finance"}}, "oidc") {
		t.Fatal("group comparison lost case")
	}
	if !identityAllowed(restricted, applicationIdentity{Subject: "user", Groups: []string{"finance"}}, "oidc") {
		t.Fatal("allowed group denied")
	}
	if identityAllowed(restricted, applicationIdentity{Groups: []string{"finance"}}, "oidc") {
		t.Fatal("anonymous identity allowed")
	}
	restricted.AllowedGroups = nil
	if _, e := normalizeApplicationAccess(restricted); e == nil {
		t.Fatal("empty group set became public")
	}
	restricted.AllowAnyAuthenticated = true
	if _, e := normalizeApplicationAccess(restricted); e != nil {
		t.Fatal(e)
	}
	if identityAllowed(restricted, applicationIdentity{}, "oidc") {
		t.Fatal("allow-any permitted unauthenticated request")
	}
	restricted.AllowAnyAuthenticated = false
	restricted.AllowedGroups = []string{"CN=Finance,OU=Groups,DC=example,DC=test"}
	if !identityAllowed(restricted, applicationIdentity{Subject: "uid=user,dc=example,dc=test", Groups: []string{"cn=finance,ou=groups,dc=example,dc=test"}}, "ldap") {
		t.Fatal("LDAP DN comparison rejected equivalent group")
	}
}

func TestIdentityHTTPBoundaries(t *testing.T) {
	called := false
	base := dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))}, nil
	})
	transport := identityHTTPTransport{base: base, origins: map[string]bool{"https://provider.test": true}}
	request, _ := http.NewRequest("GET", "https://untrusted.test/keys", nil)
	if _, err := transport.RoundTrip(request); err == nil || called {
		t.Fatal("cross-origin credential request was sent")
	}
	request, _ = http.NewRequest("GET", "https://provider.test/keys", nil)
	if _, err := transport.RoundTrip(request); err == nil || !called {
		t.Fatal("oversized provider response accepted")
	}
}
