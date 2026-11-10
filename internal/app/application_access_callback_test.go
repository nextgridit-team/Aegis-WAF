package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestOIDCCallbackParameters(t *testing.T) {
	p := storedIdentityProvider{Settings: identityProviderSettings{Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://identity.test/tenant"}}}
	valid := "state=browser-state&code=code&iss=https%3A%2F%2Fidentity.test%2Ftenant"
	for _, query := range []string{valid, "state=browser-state&code=code", "state=browser-state&error=access_denied&error_description=User+declined", valid + "&session_state=vendor-extension&scope=openid"} {
		if _, err := oidcCallbackQuery(httptest.NewRequest("GET", "https://app.test"+applicationAuthPrefix+"callback?"+query, nil), p); err != nil {
			t.Fatal("valid provider response rejected", err)
		}
	}
	for name, query := range map[string]string{
		"other issuer":      "state=x&code=y&iss=https%3A%2F%2Fother.test",
		"empty issuer":      "state=x&code=y&iss=",
		"duplicate state":   valid + "&state=other",
		"encoded duplicate": valid + "&%73tate=other",
		"duplicate issuer":  valid + "&iss=https%3A%2F%2Fidentity.test%2Ftenant",
		"duplicate code":    valid + "&code=other",
		"both outcomes":     valid + "&error=denied",
		"missing outcome":   "state=x",
		"empty code":        "state=x&code=",
		"empty error":       "state=x&error=",
		"malformed escape":  valid + "&extra=%zz",
		"semicolon":         valid + ";x=y",
		"control":           valid + "&extra=%00",
		"too many fields":   valid + strings.Repeat("&extra=x", 40),
		"too large":         valid + "&extra=" + strings.Repeat("x", 16384),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://app.test"+applicationAuthPrefix+"callback", nil)
			request.URL.RawQuery = query
			if _, err := oidcCallbackQuery(request, p); err == nil {
				t.Fatal("unsafe callback accepted")
			}
		})
	}
	request := httptest.NewRequest("GET", "https://app.test"+applicationAuthPrefix+"callback?"+valid, strings.NewReader("body"))
	if _, err := oidcCallbackQuery(request, p); err == nil {
		t.Fatal("callback body accepted")
	}
	p.Settings.Enabled = false
	request = httptest.NewRequest("GET", "https://app.test"+applicationAuthPrefix+"callback?"+valid, nil)
	if _, err := oidcCallbackQuery(request, p); err == nil {
		t.Fatal("disabled callback provider accepted")
	}
}

func TestOIDCCallbackAssignmentBoundaries(t *testing.T) {
	a, b, api, site, forwarded := captchaFixture(t)
	ctx := context.Background()
	var networkCalls atomic.Int64
	transport := dnsTestTransport(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, fmt.Errorf("unexpected provider network request")
	})
	a.identityHTTP = transport
	b.identityHTTP = transport
	providerInput := identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Expected provider", Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://expected.test", ClientID: "client"}}}
	provider := mustID(t, api.call("POST", "/api/identity-providers", providerInput, 200))
	providerInput.Name = "Another configured provider"
	providerInput.OIDC.Issuer = "https://other.test"
	other := mustID(t, api.call("POST", "/api/identity-providers", providerInput, 200))
	accessPath := fmt.Sprintf("/api/application-access/%d", site)
	access := applicationAccessInput{applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: provider, PublicOrigin: "https://bot.test", AllowedGroups: []string{"finance"}, SessionMinutes: 30}}
	api.call("PUT", accessPath, access, 200)
	// Give the same application a second legitimate hostname. It may redirect
	// normal navigation, but it must not accept or redirect authorization codes.
	if err := a.change(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE sites SET hostnames=ARRAY['bot.test','alias.test'] WHERE id=$1", site)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	for _, app := range []*App{a, b} {
		if err := app.refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state, browser := token(), token()
	insertFlow := func(providerID, revision int64, origin string, required bool) {
		t.Helper()
		if _, err := a.db.Exec(ctx, `INSERT INTO application_auth_flows(state_hash,browser_hash,site_id,provider_id,access_revision,provider_revision,origin,return_path,nonce,verifier,issuer_parameter_required,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,'/','nonce','verifier',$7,now()+interval '10 minutes')`, hash(state), hash(browser), site, providerID, revision, origin, required); err != nil {
			t.Fatal(err)
		}
	}
	insertFlow(provider, 1, "https://bot.test", false)
	callback := applicationAuthPrefix + "callback?state=" + url.QueryEscape(state) + "&code=secret-code"
	probe := func(target string, secure bool, cookie string, want int) {
		t.Helper()
		request := httptest.NewRequest("GET", target, nil)
		request.RemoteAddr = "198.51.100.9:3210"
		if secure {
			request.TLS = &tls.ConnectionState{ServerName: request.URL.Hostname()}
		} else {
			request.TLS = nil
		}
		if cookie != "" {
			request.AddCookie(&http.Cookie{Name: applicationFlowCookie, Value: cookie})
		}
		rec := httptest.NewRecorder()
		b.Public(rec, request)
		if rec.Code != want || rec.Header().Get("Location") != "" {
			t.Fatalf("callback returned %d, location=%q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		select {
		case event := <-b.access:
			if event.evidence != nil {
				t.Fatal("callback captured as evidence")
			}
		default:
			t.Fatal("missing callback metadata")
		}
		if networkCalls.Load() != 0 || forwarded.Load() != 0 {
			t.Fatal("rejected callback reached provider or application")
		}
	}
	for _, target := range []string{"https://alias.test" + callback, "http://bot.test" + callback, "https://bot.test:444" + callback, "https://bot.test/__aegis/auth/%63allback?state=" + state + "&code=x"} {
		probe(target, !strings.HasPrefix(target, "http:"), browser, 400)
	}
	probe("https://bot.test"+callback+"&iss=https%3A%2F%2Fother.test", true, browser, 400)
	probe("https://bot.test"+callback+"&state=other", true, browser, 400)
	probe("https://bot.test"+callback, true, token(), 400)
	probe("https://bot.test"+callback, true, "", 400)
	var preserved bool
	if err := a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM application_auth_flows WHERE state_hash=$1)", hash(state)).Scan(&preserved); err != nil || !preserved {
		t.Fatal("invalid callback consumed another browser's flow", err)
	}
	// An advertised issuer parameter is required before any token exchange.
	if _, err := a.db.Exec(ctx, "UPDATE application_auth_flows SET issuer_parameter_required=true WHERE state_hash=$1", hash(state)); err != nil {
		t.Fatal(err)
	}
	probe("https://bot.test"+callback, true, browser, 400)
	insertFlow(other, 1, "https://bot.test", false)
	probe("https://bot.test"+callback, true, browser, 400)
	a.db.Exec(ctx, "DELETE FROM application_auth_flows WHERE state_hash=$1", hash(state))
	insertFlow(provider, 1, "https://other-app.test", false)
	probe("https://bot.test"+callback, true, browser, 400)
	a.db.Exec(ctx, "DELETE FROM application_auth_flows WHERE state_hash=$1", hash(state))
	insertFlow(provider, 1, "https://bot.test", false)
	access.Revision = 1
	access.ProviderID = other
	api.call("PUT", accessPath, access, 200)
	probe("https://bot.test"+callback, true, browser, 400)
	// Inactive application assignments never expose a callback endpoint.
	access.Revision = 2
	access.Enabled = false
	api.call("PUT", accessPath, access, 200)
	probe("https://bot.test"+callback, true, browser, 404)
}
