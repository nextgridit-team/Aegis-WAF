package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMachineEndpointBotScoring(t *testing.T) {
	settings := defaultProtection()
	settings.BotChallenge.Enabled = true
	p, err := compileProtection(settings)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://api.test/", nil)
	request.Header.Set("User-Agent", "Mozilla/5.0")
	for _, profile := range []string{"web", "api", "streaming"} {
		app := &App{}
		score := app.botScore(p, 1, request, netip.MustParseAddr("198.51.100.2"), time.Now(), profile)
		expected := 0
		if profile == "web" {
			expected = 25
		}
		if score.Score != expected {
			t.Fatalf("%s browser signal: %+v", profile, score)
		}
		request.Header.Set("User-Agent", "sqlmap")
		if score := app.botScore(p, 1, request, netip.MustParseAddr("198.51.100.2"), time.Now(), profile); score.Score != 80 {
			t.Fatalf("%s lost scanner detection: %+v", profile, score)
		}
		request.Header.Set("User-Agent", "Mozilla/5.0")
	}
}

func TestEndpointProfileSimulation(t *testing.T) {
	settings := defaultProtection()
	settings.BotMode = "block"
	settings.BotChallenge.Enabled = true
	policy, err := compileProtection(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"web", "api", "streaming"} {
		snapshot := &snapshot{routes: map[string]*route{"api.test": {site: Site{ID: 1, TrafficProfile: profile}}}, protection: map[int64]*protectionPolicy{1: policy}}
		outcome, _, err := simulatePayload(context.Background(), &App{}, snapshot, simulationPayload{Host: "api.test", Headers: map[string]string{"User-Agent": "HeadlessChrome"}})
		expected := "block"
		if profile == "web" {
			expected = "challenge"
		}
		if err != nil || outcome != expected {
			t.Fatalf("%s simulation mismatch: %s %v", profile, outcome, err)
		}
	}
}

func TestMachineEndpointBotIntegration(t *testing.T) {
	a, b, api, id, forwarded := captchaFixture(t)
	upstream := a.active.Load().routes["bot.test"].site.Upstream
	p := defaultProtection()
	p.BotMode = "block"
	p.BotChallenge.Enabled = true
	for _, profile := range []string{"api", "streaming"} {
		input := map[string]any{"name": "Machine endpoint", "hostnames": []string{"bot.test"}, "upstream": upstream, "enabled": true, "traffic_profile": profile, "protection": p}
		api.call("PUT", fmt.Sprintf("/api/sites/%d", id), input, 200)
		for _, replica := range []*App{a, b} {
			if err := replica.refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if replica.active.Load().routes["bot.test"].site.TrafficProfile != profile {
				t.Fatal("profile not refreshed")
			}
			before := forwarded.Load()
			response, event := botProbe(t, replica, "POST", "/v1/chat/completions", "HeadlessChrome", "prompt=test")
			var body map[string]any
			if response.Code != 403 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["error"] != "gateway_protection_denied" || len(response.Result().Cookies()) != 0 || event.bot.Decision != "blocked" || !event.blocked || forwarded.Load() != before {
				t.Fatalf("machine request challenged/bypassed: %d %s %+v", response.Code, response.Body, event.bot)
			}
			response, _ = botProbe(t, replica, "GET", botChallengePrefix, "curl/8", "")
			if response.Code != 404 || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
				t.Fatal("browser endpoint active", response.Code)
			}
			response, event = botProbe(t, replica, "GET", "/v1/models", "curl/8", "")
			if response.Code != 200 || event.blocked || response.Body.String() != "application" {
				t.Fatal("legitimate API client rejected")
			}
		}
	}
	var challenges int
	if err := a.db.QueryRow(context.Background(), "SELECT count(*) FROM bot_challenges").Scan(&challenges); err != nil || challenges != 0 {
		t.Fatal("machine endpoint issued challenge", challenges, err)
	}
}

func TestAPIProfileRetainsManagedInspection(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"error":"`+sqlLeak+`"}`)
	}))
	defer up.Close()
	app := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: "block", BodyLimit: 4096})
	route := app.active.Load().routes["managed.test"]
	route.site.TrafficProfile = "api"
	target, _ := url.Parse(up.URL)
	route.proxy = newSiteProxy(target, route.site, HeaderSettings{})
	for _, test := range []struct {
		body   string
		status int
		code   string
	}{
		{`{"search":"1' UNION SELECT password FROM users --"}`, 403, "managed_signature_rejected"},
		{`{"text":"` + strings.Repeat("x", 5000) + `"}`, 413, "managed_signature_rejected"},
		{`{"text":"hello"}`, 502, "response_rejected"},
	} {
		request := httptest.NewRequest("POST", "http://managed.test/v1/chat/completions", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "curl/8")
		request.Header.Set("Accept", "application/json")
		response := httptest.NewRecorder()
		app.Public(response, request)
		var body map[string]string
		if response.Code != test.status || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["error"] != test.code {
			t.Fatalf("inspection bypassed or wrong error: %d %s", response.Code, response.Body)
		}
		event := <-app.access
		if !event.blocked || event.responseSource != "waf" {
			t.Fatal("missing block provenance", event.responseSource)
		}
	}
}
