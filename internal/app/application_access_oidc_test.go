package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestApplicationOIDCAndReplicaEnforcement(t *testing.T) {
	a, b, api, site, forwarded := captchaFixture(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	var lock sync.Mutex
	claims := map[string]any{}
	challenge := ""
	issuer := ""
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			r.ParseForm()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			client, secret, _ := r.BasicAuth()
			if r.Form.Get("redirect_uri") != "https://bot.test/__aegis/auth/callback" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || client != "aegis" || secret != "test-secret" {
				t.Error("invalid PKCE/client/callback exchange")
				http.Error(w, "bad exchange", 400)
				return
			}
			raw, _ := json.Marshal(claims)
			signed, _ := signer.Sign(raw)
			jwt, _ := signed.CompactSerialize()
			json.NewEncoder(w).Encode(map[string]any{"access_token": "unused-access-token", "token_type": "Bearer", "expires_in": 600, "id_token": jwt})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()
	issuer = idp.URL
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw}))
	input := identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Test OIDC", Type: "oidc", Enabled: true, CAPEM: ca, OIDC: &oidcSettings{Issuer: issuer, ClientID: "aegis"}}, Secret: "test-secret"}
	provider := mustID(t, api.call("POST", "/api/identity-providers", input, 200))
	access := applicationAccessInput{applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: provider, PublicOrigin: "https://bot.test", AllowedGroups: []string{"finance"}, SessionMinutes: 30}}
	accessPath := fmt.Sprintf("/api/application-access/%d", site)
	api.call("PUT", accessPath, access, 200)
	for _, app := range []*App{a, b} {
		if e = app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if result := api.call("POST", fmt.Sprintf("/api/identity-providers/%d/test", provider), map[string]any{}, 200); !strings.Contains(string(result), `"ok":true`) {
		t.Fatal(string(result))
	}
	probe := func(app *App, method, path, form string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		w, event := botProbe(t, app, method, path, "Mozilla/5.0", form, cookies...)
		if strings.HasPrefix(path, applicationAuthPrefix) && event.evidence != nil {
			t.Fatal("authentication captured as traffic evidence")
		}
		return w
	}
	unauth := probe(a, "GET", "/private?x=1", "")
	if unauth.Code != 302 || forwarded.Load() != 0 {
		t.Fatal("anonymous request forwarded", unauth.Code)
	}
	if w := probe(a, "POST", "/private", "secret=not-forwarded"); w.Code != 401 || forwarded.Load() != 0 {
		t.Fatal("API did not fail closed", w.Code)
	}
	login := func(mutate func(map[string]any)) (*httptest.ResponseRecorder, string, *http.Cookie) {
		t.Helper()
		w := probe(a, "GET", applicationAuthPrefix+"login?return=%2Fprivate%3Fx%3D1", "")
		if w.Code != 302 {
			t.Fatalf("login start %d: %s", w.Code, w.Body.String())
		}
		dest, e := url.Parse(w.Header().Get("Location"))
		if e != nil {
			t.Fatal(e)
		}
		q := dest.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
			t.Fatal("missing OIDC protections", q)
		}
		lock.Lock()
		challenge = q.Get("code_challenge")
		claims = map[string]any{"iss": issuer, "aud": "aegis", "sub": "user-1", "preferred_username": "alice", "email": "alice@example.test", "groups": []string{"finance"}, "iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(), "nonce": q.Get("nonce")}
		if mutate != nil {
			mutate(claims)
		}
		lock.Unlock()
		var browser *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == applicationFlowCookie {
				browser = c
			}
		}
		if browser == nil || !browser.Secure || !browser.HttpOnly || browser.SameSite != http.SameSiteLaxMode || browser.Domain != "" {
			t.Fatal("unsafe flow cookie")
		}
		path := applicationAuthPrefix + "callback?state=" + url.QueryEscape(q.Get("state")) + "&code=valid-code"
		return probe(b, "GET", path, "", browser), path, browser
	}
	signedIn, callback, browser := login(nil)
	if signedIn.Code != 303 || signedIn.Header().Get("Location") != "https://bot.test/private?x=1" {
		t.Fatalf("sign in %d %s", signedIn.Code, signedIn.Body.String())
	}
	var session *http.Cookie
	for _, c := range signedIn.Result().Cookies() {
		if c.Name == applicationSessionCookie {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Domain != "" {
		t.Fatal("unsafe session cookie")
	}
	for _, app := range []*App{a, b} {
		w := probe(app, "GET", "/private", "", session)
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") != "" {
			t.Fatal("valid session rejected or login headers leaked", w.Code, w.Header())
		}
	}
	if w := probe(a, "GET", callback, "", browser); w.Code != 400 {
		t.Fatal("OIDC callback replay accepted", w.Code)
	}
	api.call("POST", accessPath+"/revoke", map[string]any{}, 200)
	if w := probe(b, "GET", "/private", "", session); w.Code != 302 {
		t.Fatal("revoked session still active", w.Code)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		status int
	}{
		{"nonce", func(c map[string]any) { c["nonce"] = "wrong" }, 401},
		{"issuer", func(c map[string]any) { c["iss"] = "https://wrong.test" }, 401},
		{"audience", func(c map[string]any) { c["aud"] = "other-client" }, 401},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, 401},
		{"party", func(c map[string]any) { c["aud"] = []string{"aegis", "other"} }, 401},
		{"group", func(c map[string]any) { c["groups"] = []string{"engineering"} }, 403},
		{"overage", func(c map[string]any) {
			delete(c, "groups")
			c["_claim_names"] = map[string]string{"groups": "src1"}
			c["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": "https://graph.microsoft.com/v1.0/me/memberOf"}}
		}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.db.Exec(context.Background(), "DELETE FROM login_limits")
			w, _, _ := login(tc.mutate)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	a.db.Exec(context.Background(), "DELETE FROM login_limits")
	signedIn, _, _ = login(nil)
	for _, c := range signedIn.Result().Cookies() {
		if c.Name == applicationSessionCookie {
			session = c
		}
	}
	input.Revision = 1
	input.Enabled = false
	input.Secret = ""
	api.call("PUT", fmt.Sprintf("/api/identity-providers/%d", provider), input, 200)
	if w := probe(b, "GET", "/private", "", session); w.Code != 503 {
		t.Fatal("disabled provider allowed access", w.Code)
	}
	sealed, e := b.archiveSnapshot(b.active.Load(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	restored, e := b.decodeSnapshot(sealed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	b.active.Store(restored)
	b.db.Close()
	if w := probe(b, "GET", "/private", "", session); w.Code != 503 {
		t.Fatal("database outage allowed access", w.Code)
	}
}

func TestApplicationCredentialBoundaries(t *testing.T) {
	for _, value := range []string{"//evil.test", "/%2fevil.test", "/\\evil.test", "https://evil.test", "/__aegis/auth/callback?code=x", "/%0d%0aX:y"} {
		if safeApplicationReturn(value) != "/" {
			t.Fatal("unsafe return", value)
		}
	}
	request := httptest.NewRequest("GET", "https://app.test/", nil)
	request.Header.Set("X-Aegis-Identity-User", "spoofed")
	request.Header.Set("Cookie", "normal=keep; "+applicationSessionCookie+"=secret; "+applicationFlowCookie+"=state")
	stripApplicationCredentials(request)
	if request.Header.Get("X-Aegis-Identity-User") != "" || request.Header.Get("Cookie") != "normal=keep" {
		t.Fatal("gateway identity leaked", request.Header)
	}
}
