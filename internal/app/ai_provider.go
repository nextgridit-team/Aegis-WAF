package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type aiProviderInput struct {
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
	ClearAPIKey bool   `json:"clear_api_key"`
	Model       string `json:"model"`
	Revision    int64  `json:"revision"`
}
type aiProviderView struct {
	Configured bool       `json:"configured"`
	BaseURL    string     `json:"base_url"`
	HasAPIKey  bool       `json:"has_api_key"`
	Model      string     `json:"model"`
	Models     []string   `json:"models"`
	CheckedAt  *time.Time `json:"checked_at"`
	Revision   int64      `json:"revision"`
}
type aiStoredProvider struct {
	aiProviderView
	cipher []byte
	keyID  string
}

func aiBaseURL(raw string) (string, error) {
	if len(raw) > 2048 {
		return "", invalid("AI base URL is too long")
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", invalid("use an HTTP(S) API base URL without credentials, query parameters or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/v1"
	}
	u.RawPath = ""
	if strings.HasSuffix(u.Path, "/models") || strings.HasSuffix(u.Path, "/chat/completions") || strings.HasSuffix(u.Path, "/responses") {
		return "", invalid("enter the API base URL, such as https://api.openai.com/v1, rather than a request endpoint")
	}
	return u.String(), nil
}
func (a *App) readAIProvider(ctx context.Context) (aiStoredProvider, error) {
	out := aiStoredProvider{aiProviderView: aiProviderView{Models: []string{}}}
	var raw []byte
	e := a.db.QueryRow(ctx, "SELECT base_url,key_cipher,key_id,model,models,checked_at,revision FROM ai_provider WHERE id").Scan(&out.BaseURL, &out.cipher, &out.keyID, &out.Model, &raw, &out.CheckedAt, &out.Revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(raw, &out.Models); e != nil {
		return out, e
	}
	out.Configured = true
	out.HasAPIKey = len(out.cipher) > 0
	return out, nil
}
func (a *App) aiCredentials(ctx context.Context, input aiProviderInput) (aiProviderInput, aiStoredProvider, error) {
	previous, e := a.readAIProvider(ctx)
	if e != nil {
		return input, previous, e
	}
	input.BaseURL, e = aiBaseURL(input.BaseURL)
	if e != nil {
		return input, previous, e
	}
	if input.ClearAPIKey && input.APIKey != "" {
		return input, previous, invalid("provide a key or select No API key, not both")
	}
	if len(input.APIKey) > 4096 {
		return input, previous, invalid("AI API key is too long")
	}
	for _, c := range input.APIKey {
		if c < 33 || c > 126 {
			return input, previous, invalid("enter a raw API key without whitespace or control characters")
		}
	}
	if input.ClearAPIKey {
		return input, previous, nil
	}
	if input.APIKey == "" && previous.HasAPIKey {
		if previous.BaseURL != input.BaseURL {
			return input, previous, invalid("enter a new key or choose No API key when changing the endpoint")
		}
		if previous.keyID != a.cfg.KeyID {
			return input, previous, errors.New("AI credential encryption key is unavailable")
		}
		key, e := open(a.cfg.Key, previous.keyID+":ai-provider:"+previous.BaseURL, previous.cipher)
		if e != nil {
			return input, previous, e
		}
		input.APIKey = string(key)
	}
	return input, previous, nil
}
func aiTargetIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && (ip.IsGlobalUnicast() || ip.IsLoopback()) && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && ip.String() != "100.100.100.200" && ip.String() != "fd00:ec2::254"
}
func discoverAIModels(ctx context.Context, base, key string) ([]string, error) {
	parsed, e := url.Parse(base)
	if e != nil {
		return nil, invalid("invalid AI base URL")
	}
	transport := &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("AI hostname lookup failed")
		}
		for _, ip := range ips {
			if !aiTargetIP(ip) {
				return nil, errors.New("AI endpoint resolves to a prohibited address")
			}
			if parsed.Scheme == "http" && !ip.IsPrivate() && !ip.IsLoopback() {
				return nil, errors.New("public AI endpoints require HTTPS")
			}
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		var last error
		for _, ip := range ips {
			var c net.Conn
			c, last = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if last == nil {
				return c, nil
			}
		}
		return nil, last
	}}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", base+"/models", nil)
	if e != nil {
		return nil, invalid("invalid AI model-list URL")
	}
	req.Header.Set("Accept", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, apiError{502, "AI model discovery failed; check DNS, reachability, HTTPS trust and the API base URL. HTTP is supported only on private/local addresses."}
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 200:
	case 401, 403:
		return nil, apiError{502, "AI endpoint rejected authentication or model-list access"}
	case 404:
		return nil, apiError{502, "AI endpoint has no models route; check that the base URL includes the API prefix, usually /v1"}
	case 429:
		return nil, apiError{502, "AI endpoint rate-limited model discovery; retry later"}
	default:
		return nil, apiError{502, "AI endpoint did not return a successful model list; redirects are not followed"}
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return nil, apiError{502, "AI model-list response was unreadable or exceeded 2 MiB"}
	}
	var document struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if e = json.Unmarshal(raw, &document); e != nil || document.Data == nil || len(document.Data) > 1000 {
		return nil, apiError{502, "AI endpoint did not return a supported OpenAI-compatible model list"}
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, model := range document.Data {
		if len(model.ID) < 1 || len(model.ID) > 256 || strings.TrimSpace(model.ID) != model.ID {
			return nil, apiError{502, "AI endpoint returned an invalid model identifier"}
		}
		for _, c := range model.ID {
			if c < 32 || c == 127 {
				return nil, apiError{502, "AI endpoint returned an invalid model identifier"}
			}
		}
		if !seen[model.ID] {
			seen[model.ID] = true
			ids = append(ids, model.ID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}
func (a *App) testAIProvider(w http.ResponseWriter, r *http.Request, i identity) error {
	var input aiProviderInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	resolved, _, e := a.aiCredentials(r.Context(), input)
	if e != nil {
		return e
	}
	models, discoveryErr := discoverAIModels(r.Context(), resolved.BaseURL, resolved.APIKey)
	action := "ai.provider.tested"
	if discoveryErr != nil {
		action = "ai.provider.test_failed"
	}
	if _, e = a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES($1,$2,'model-discovery')", i.Username, action); e != nil {
		return e
	}
	if discoveryErr != nil {
		return discoveryErr
	}
	respond(w, 200, map[string]any{"models": models, "base_url": resolved.BaseURL, "inference_tested": false})
	return nil
}
func (a *App) saveAIProvider(w http.ResponseWriter, r *http.Request, i identity) error {
	var input aiProviderInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	resolved, previous, e := a.aiCredentials(r.Context(), input)
	if e != nil {
		return e
	}
	if previous.Revision != input.Revision {
		return apiError{409, "AI provider changed; reload settings before saving"}
	}
	models, e := discoverAIModels(r.Context(), resolved.BaseURL, resolved.APIKey)
	if e != nil {
		return e
	}
	found := false
	for _, id := range models {
		if id == input.Model {
			found = true
		}
	}
	if !found {
		return invalid("select a model returned by this endpoint")
	}
	var ciphertext []byte
	if resolved.APIKey != "" {
		ciphertext, e = seal(a.cfg.Key, a.cfg.KeyID+":ai-provider:"+resolved.BaseURL, []byte(resolved.APIKey))
		if e != nil {
			return e
		}
	}
	rawModels, _ := json.Marshal(models)
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var revision int64
		if e := tx.QueryRow(r.Context(), "SELECT coalesce((SELECT revision FROM ai_provider WHERE id),0)").Scan(&revision); e != nil {
			return e
		}
		if revision != input.Revision {
			return apiError{409, "AI provider changed; reload settings before saving"}
		}
		if _, e := tx.Exec(r.Context(), "INSERT INTO ai_provider(id,base_url,key_cipher,key_id,model,models,checked_at,revision) VALUES(true,$1,$2,$3,$4,$5,now(),$6) ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url,key_cipher=excluded.key_cipher,key_id=excluded.key_id,model=excluded.model,models=excluded.models,checked_at=excluded.checked_at,revision=excluded.revision", resolved.BaseURL, ciphertext, a.cfg.KeyID, input.Model, rawModels, revision+1); e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "ai.provider.saved", "provider")
	})
	if e != nil {
		return e
	}
	current, e := a.readAIProvider(r.Context())
	if e != nil {
		return e
	}
	respond(w, 200, current.aiProviderView)
	return nil
}
func aiAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/ai/provider", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		provider, e := a.readAIProvider(r.Context())
		if e != nil {
			return e
		}
		respond(w, 200, provider.aiProviderView)
		return nil
	}))
	m.HandleFunc("POST /api/ai/provider/test", a.wrap(true, a.testAIProvider))
	m.HandleFunc("PUT /api/ai/provider", a.wrap(true, a.saveAIProvider))
	m.HandleFunc("DELETE /api/ai/provider", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		var body struct {
			Revision int64 `json:"revision"`
		}
		if e := decode(w, r, &body); e != nil {
			return e
		}
		e := a.change(r.Context(), func(tx pgx.Tx) error {
			tag, e := tx.Exec(r.Context(), "DELETE FROM ai_provider WHERE id AND revision=$1", body.Revision)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return apiError{409, "AI provider changed or was already removed; reload settings"}
			}
			return audit(r.Context(), tx, i.Username, "ai.provider.removed", "provider")
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"removed": true})
		return nil
	}))
}
