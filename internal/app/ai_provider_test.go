package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAIModelDiscovery(t *testing.T) {
	var seen atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("wrong endpoint/auth")
		}
		io.WriteString(w, `{"data":[{"id":"z-model"},{"id":"a-model"},{"id":"a-model"}]}`)
	}))
	defer s.Close()
	base, e := aiBaseURL(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	models, e := discoverAIModels(context.Background(), base, "test-secret")
	if e != nil || len(models) != 2 || models[0] != "a-model" || seen.Load() != 1 {
		t.Fatal(models, e)
	}
	for _, raw := range []string{"file:///etc/passwd", "https://key:secret@example.com/v1", "https://example.com/v1?key=secret", "https://example.com/v1/models"} {
		if _, e := aiBaseURL(raw); e == nil {
			t.Fatal("accepted invalid base URL", raw)
		}
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.URL+"/v1/models", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if _, e := discoverAIModels(context.Background(), redirect.URL, "test-secret"); e == nil || seen.Load() != 1 {
		t.Fatal("AI redirect followed or accepted")
	}
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"error":{"message":"test-secret"}}`) }))
	defer invalid.Close()
	if _, e := discoverAIModels(context.Background(), invalid.URL, ""); e == nil || strings.Contains(e.Error(), "test-secret") {
		t.Fatal("raw provider error leaked")
	}
}
func TestAIProviderIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	m := httptest.NewServer(a.Management())
	defer m.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, m.URL, ""}
	c.call("GET", "/api/ai/provider", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "AI provider long test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "AI provider long test password"}, 200), &login)
	c.csrf = login["csrf"]
	var status atomic.Int64
	status.Store(200)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Error("unexpected inference call", r.URL.Path)
		}
		if status.Load() != 200 {
			w.WriteHeader(int(status.Load()))
			io.WriteString(w, `{"error":"test-provider-key"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-provider-key" {
			t.Error("missing bearer key")
		}
		io.WriteString(w, `{"data":[{"id":"test-model"}]}`)
	}))
	defer provider.Close()
	input := aiProviderInput{BaseURL: provider.URL, APIKey: "test-provider-key", Model: "test-model"}
	savedCSRF := c.csrf
	c.csrf = "wrong"
	c.call("POST", "/api/ai/provider/test", input, 403)
	c.csrf = savedCSRF
	c.call("POST", "/api/ai/provider/test", input, 200)
	var view aiProviderView
	json.Unmarshal(c.call("GET", "/api/ai/provider", nil, 200), &view)
	if view.Configured {
		t.Fatal("preview persisted a provider")
	}
	json.Unmarshal(c.call("PUT", "/api/ai/provider", input, 200), &view)
	if !view.HasAPIKey || view.Model != "test-model" || view.Revision != 1 {
		t.Fatal(view)
	}
	raw := c.call("GET", "/api/ai/provider", nil, 200)
	if strings.Contains(string(raw), "test-provider-key") || strings.Contains(string(raw), "cipher") {
		t.Fatal("API returned stored key")
	}
	var ciphertext []byte
	a.db.QueryRow(context.Background(), "SELECT key_cipher FROM ai_provider WHERE id").Scan(&ciphertext)
	if strings.Contains(string(ciphertext), "test-provider-key") {
		t.Fatal("key stored plaintext")
	}
	input.APIKey = ""
	input.BaseURL = view.BaseURL
	input.Revision = 1
	c.call("POST", "/api/ai/provider/test", input, 200)
	input.BaseURL = provider.URL + "/other"
	c.call("POST", "/api/ai/provider/test", input, 400)
	input.BaseURL = view.BaseURL
	status.Store(401)
	errorBody := c.call("PUT", "/api/ai/provider", input, 502)
	if strings.Contains(string(errorBody), "test-provider-key") {
		t.Fatal("provider body leaked in error")
	}
	json.Unmarshal(c.call("GET", "/api/ai/provider", nil, 200), &view)
	if view.Revision != 1 || !view.HasAPIKey {
		t.Fatal("failed save replaced working provider")
	}
	status.Store(200)
	c.call("PUT", "/api/ai/provider", aiProviderInput{BaseURL: provider.URL, APIKey: "test-provider-key", Model: "test-model", Revision: 0}, 409)
	c.call("DELETE", "/api/ai/provider", map[string]int64{"revision": 1}, 200)
	json.Unmarshal(c.call("GET", "/api/ai/provider", nil, 200), &view)
	if view.Configured || view.HasAPIKey {
		t.Fatal("provider/key not removed")
	}
}
