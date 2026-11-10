package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentityProviderManagement(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	input := identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Company", Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://identity.example.test", ClientID: "aegis"}}, Secret: "provider-secret-do-not-return"}
	id := mustID(t, api.call("POST", "/api/identity-providers", input, 200))
	path := fmt.Sprintf("/api/identity-providers/%d", id)
	read := api.call("GET", path, nil, 200)
	if strings.Contains(string(read), input.Secret) || strings.Contains(string(read), "cipher") || !strings.Contains(string(read), `"has_secret":true`) {
		t.Fatal("secret redaction failed", string(read))
	}
	var p storedIdentityProvider
	json.Unmarshal(read, &p)
	if p.Revision != 1 {
		t.Fatal(p.Revision)
	}
	saved, e := readIdentityProvider(context.Background(), a.db, id)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := a.identitySecret(saved)
	if e != nil || secret != input.Secret {
		t.Fatal("encrypted secret roundtrip failed", e)
	}
	input.Revision = 1
	input.Secret = ""
	input.Name = "Renamed provider"
	api.call("PUT", path, input, 200)
	api.call("PUT", path, input, 409)
	input.Revision = 2
	input.OIDC.Issuer = "https://different.example.test"
	api.call("PUT", path, input, 400)
	access := applicationAccessInput{Revision: 0, applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: id, PublicOrigin: "https://bot.test", AllowedGroups: []string{"finance"}, SessionMinutes: 30}}
	accessPath := fmt.Sprintf("/api/application-access/%d", site)
	api.call("PUT", accessPath, access, 200)
	api.call("PUT", accessPath, access, 409)
	api.call("DELETE", path, nil, 409)
	access.Revision = 1
	access.PublicOrigin = "https://evil.test"
	api.call("PUT", accessPath, access, 400)
	access.PublicOrigin = "https://bot.test"
	access.Enabled = false
	access.ProviderID = 0
	api.call("PUT", accessPath, access, 200)
	api.call("DELETE", path, nil, 200)
	for _, route := range []string{"/api/identity-providers", "/api/identity-providers/presets", "/api/application-access", "/api/application-sessions"} {
		api.call("GET", route, nil, 200)
	}
}

func TestApplicationAccessIndependentOfInspection(t *testing.T) {
	a, _, api, site, forwarded := captchaFixture(t)
	id := mustID(t, api.call("POST", "/api/identity-providers", identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Independent access", Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://identity.example.test", ClientID: "aegis"}}}, 200))
	access := applicationAccessInput{applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: id, PublicOrigin: "https://bot.test", AllowedGroups: []string{"finance"}, SessionMinutes: 30}}
	api.call("PUT", fmt.Sprintf("/api/application-access/%d", site), access, 200)
	for _, mode := range []string{"off", "observe", "block"} {
		p := defaultProtection()
		p.Mode = mode
		api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), p, 200)
		if err := a.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		// Install a full network bypass in the active policy to test its precedence.
		s := a.active.Load()
		network, err := compileNetworkAccess(networkAccessSettings{AllowCIDRs: []string{"198.51.100.0/24"}, AllowScope: "all"}, "block")
		if err != nil {
			t.Fatal(err)
		}
		s.protection[site].network = network
		for _, binding := range s.policyBindings[site] {
			binding.Protection.network = network
		}
		w, _ := botProbe(t, a, "GET", "/private", "Mozilla/5.0", "")
		if w.Code != 302 || forwarded.Load() != 0 {
			t.Fatal("inspection bypass removed login requirement", mode, w.Code)
		}
	}
	req := httptest.NewRequest("POST", "http://bot.test"+applicationAuthPrefix+"login", strings.NewReader("password=must-not-forward"))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	a.Public(rec, req)
	if rec.Code != 426 || forwarded.Load() != 0 {
		t.Fatal("untrusted forwarded HTTPS accepted", rec.Code)
	}
}
