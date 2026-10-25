package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/jackc/pgx/v5"
)

var cloudflareTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,256}$`)

func (a *App) saveDNSCredential(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct {
		Name     string `json:"name"`
		APIToken string `json:"api_token"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Name = strings.TrimSpace(body.Name)
	body.APIToken = strings.TrimSpace(body.APIToken)
	if body.Name == "" || len(body.Name) > 120 {
		return invalid("name must contain 1–120 bytes")
	}
	var id int64
	var e error
	if r.Method == "PUT" {
		id, e = resourceID(r)
		if e != nil {
			return e
		}
	}
	if body.APIToken == "" && id == 0 {
		return invalid("a Cloudflare API token is required")
	}
	if body.APIToken != "" && !cloudflareTokenPattern.MatchString(body.APIToken) {
		return invalid("provide a Cloudflare API token, without a Bearer prefix")
	}
	var cipher []byte
	if body.APIToken != "" {
		cipher, e = seal(a.cfg.Key, a.cfg.KeyID+":dns-credential", []byte(body.APIToken))
		if e != nil {
			return e
		}
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		if id == 0 {
			if e := tx.QueryRow(r.Context(), "INSERT INTO dns_credentials(name,token_cipher,key_id) VALUES($1,$2,$3) RETURNING id", body.Name, cipher, a.cfg.KeyID).Scan(&id); e != nil {
				return e
			}
		} else {
			tag, e := tx.Exec(r.Context(), "UPDATE dns_credentials SET name=$2,token_cipher=CASE WHEN $3::bytea IS NULL THEN token_cipher ELSE $3 END,key_id=CASE WHEN $3::bytea IS NULL THEN key_id ELSE $4 END,updated_at=now() WHERE id=$1", id, body.Name, cipher, a.cfg.KeyID)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 0 {
				return apiError{404, "DNS credential not found"}
			}
		}
		return audit(r.Context(), tx, i.Username, "dns.credential.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) deleteDNSCredential(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var used bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM certificates WHERE dns_credential_id=$1 UNION ALL SELECT 1 FROM dns_challenges WHERE credential_id=$1)", id).Scan(&used); e != nil {
			return e
		}
		if used {
			return apiError{409, "this credential is assigned to a certificate"}
		}
		tag, e := tx.Exec(r.Context(), "DELETE FROM dns_credentials WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return apiError{404, "DNS credential not found"}
		}
		return audit(r.Context(), tx, i.Username, "dns.credential.deleted", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
func dnsAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/dns/credentials", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, "SELECT id,name,'cloudflare' AS provider,created_at,updated_at FROM dns_credentials ORDER BY id")
	}))
	m.HandleFunc("POST /api/dns/credentials", a.wrap(true, a.saveDNSCredential))
	m.HandleFunc("PUT /api/dns/credentials/{id}", a.wrap(true, a.saveDNSCredential))
	m.HandleFunc("DELETE /api/dns/credentials/{id}", a.wrap(true, a.deleteDNSCredential))
}
func certificateDomains(in []string, challenge string) ([]string, error) {
	if len(in) < 1 || len(in) > 100 {
		return nil, errors.New("provide 1–100 hostnames")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, h := range in {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		wild := strings.HasPrefix(h, "*.")
		if wild && challenge != "dns-01" {
			return nil, errors.New("wildcard certificates require DNS-01")
		}
		base := h
		if wild {
			base = h[2:]
		}
		v, e := hostname(base)
		if e != nil {
			return nil, e
		}
		if wild {
			v = "*." + v
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

type dnsProvider interface {
	Present(string, string, string) error
	CleanUp(string, string, string) error
}
type dnsPresentation struct{ host, token, response string }
type cloudflareChallenge struct {
	provider  dnsProvider
	presented []dnsPresentation
	cleanup   func(context.Context, int64) error
}

func newCloudflareChallenge(ctx context.Context, token string, client *http.Client) (*cloudflareChallenge, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, Transport: challengeTransport{ctx: ctx}}
	}
	provider, e := cloudflare.NewDNSProviderConfig(&cloudflare.Config{AuthToken: token, ZoneToken: token, TTL: 120, PropagationTimeout: 2 * time.Minute, PollingInterval: 2 * time.Second, HTTPClient: client})
	if e != nil {
		return nil, errors.New("Cloudflare provider configuration failed")
	}
	return &cloudflareChallenge{provider: provider}, nil
}

// The provider performs DNS discovery, TXT creation and cleanup. Bound all API
// operations to the job; cleanup still has a short independent cancellation budget.
type challengeTransport struct {
	ctx    context.Context
	record func(string, string) error
	base   http.RoundTripper
}

func (t challengeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := t.ctx
	cancel := func() {}
	if r.Method == http.MethodDelete {
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	}
	defer cancel()
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, e := base.RoundTrip(r.Clone(ctx))
	if e != nil || t.record == nil || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/dns_records") || response.StatusCode < 200 || response.StatusCode >= 300 {
		return response, e
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(data))
	if e != nil {
		return response, e
	}
	var result struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &result) != nil || result.Result.ID == "" {
		return response, nil
	}
	parts := strings.Split(r.URL.Path, "/")
	zone := parts[len(parts)-2]
	if e = t.record(zone, result.Result.ID); e != nil {
		// If persistence fails after creation, immediately undo that one record.
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(cleanup, http.MethodDelete, r.URL.String()+"/"+url.PathEscape(result.Result.ID), nil)
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		res, _ := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if res != nil {
			res.Body.Close()
		}
		response.Body.Close()
		return nil, errors.New("DNS challenge persistence failed")
	}
	return response, nil
}
func (p *cloudflareChallenge) Present(ctx context.Context, host, token, response string, job int64) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := p.provider.Present(host, token, response); e != nil {
		return invalid("Cloudflare TXT creation failed; check token Zone Read / DNS Edit permissions and zone access")
	}
	p.presented = append(p.presented, dnsPresentation{host, token, response})
	return nil
}
func (p *cloudflareChallenge) CleanUp(ctx context.Context, job int64) error {
	if p.cleanup != nil {
		return p.cleanup(ctx, job)
	}
	var result error
	for _, v := range p.presented {
		if e := p.provider.CleanUp(v.host, v.token, v.response); e != nil {
			result = errors.New("Cloudflare TXT cleanup failed")
		}
	}
	return result
}
func waitDNSRecord(ctx context.Context, host, response string) error {
	info := dns01.GetChallengeInfo(host, response)
	// Public resolvers avoid mistaking private split-DNS records for propagation.
	for {
		for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, server)
			}}
			query, cancel := context.WithTimeout(ctx, 4*time.Second)
			values, e := resolver.LookupTXT(query, info.EffectiveFQDN)
			cancel()
			if e == nil {
				for _, value := range values {
					if value == info.Value {
						return nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("DNS propagation timed out; check Cloudflare zone access and public DNS")
		case <-time.After(2 * time.Second):
		}
	}
}
func (a *App) cloudflareForCertificate(ctx context.Context, id, job int64) (*cloudflareChallenge, error) {
	var cipher []byte
	var keyID string
	if e := a.db.QueryRow(ctx, "SELECT d.token_cipher,d.key_id FROM certificates c JOIN dns_credentials d ON d.id=c.dns_credential_id WHERE c.id=$1", id).Scan(&cipher, &keyID); e != nil {
		return nil, e
	}
	if keyID != a.cfg.KeyID {
		return nil, errors.New("unknown DNS credential key identifier")
	}
	token, e := open(a.cfg.Key, keyID+":dns-credential", cipher)
	if e != nil {
		return nil, e
	}
	transport := challengeTransport{ctx: ctx, base: a.dnsTransport, record: func(zone, record string) error {
		_, e := a.db.Exec(ctx, "INSERT INTO dns_challenges(job_id,credential_id,zone_id,record_id) SELECT $1,dns_credential_id,$3,$4 FROM certificates WHERE id=$2", job, id, zone, record)
		return e
	}}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	var provider *cloudflareChallenge
	if a.dnsFactory != nil {
		provider, e = a.dnsFactory(ctx, string(token), client)
	} else {
		provider, e = newCloudflareChallenge(ctx, string(token), client)
	}
	if e != nil {
		return nil, e
	}
	provider.cleanup = func(cleanup context.Context, job int64) error { return a.cleanupDNSRecords(cleanup, job, false) }
	return provider, nil
}

var _ ChallengeProvider = (*cloudflareChallenge)(nil)

// Cleanup uses persisted record IDs, so another replica can recover after a crash.
// Only records created by this application are removed, never unrelated TXT data.
func (a *App) cleanupDNSRecords(ctx context.Context, job int64, oldOnly bool) error {
	rows, e := a.db.Query(ctx, `SELECT c.id,c.zone_id,c.record_id,d.token_cipher,d.key_id FROM dns_challenges c JOIN dns_credentials d ON d.id=c.credential_id WHERE ($1::bigint=0 OR c.job_id=$1) AND (NOT $2 OR c.created_at<now()-interval '10 minutes') ORDER BY c.id LIMIT 200`, job, oldOnly)
	if e != nil {
		return e
	}
	type item struct {
		id                int64
		zone, record, key string
		cipher            []byte
	}
	items := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.id, &i.zone, &i.record, &i.cipher, &i.key); e != nil {
			rows.Close()
			return e
		}
		items = append(items, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, i := range items {
		if i.key != a.cfg.KeyID {
			return errors.New("unknown DNS credential key")
		}
		token, e := open(a.cfg.Key, i.key+":dns-credential", i.cipher)
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodDelete, "https://api.cloudflare.com/client/v4/zones/"+url.PathEscape(i.zone)+"/dns_records/"+url.PathEscape(i.record), nil)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		response, e := (&http.Client{Timeout: 15 * time.Second, Transport: a.dnsTransport}).Do(req)
		if e != nil {
			return errors.New("Cloudflare TXT cleanup unavailable")
		}
		var result struct {
			Success bool `json:"success"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result)
		response.Body.Close()
		if response.StatusCode != 404 && (response.StatusCode < 200 || response.StatusCode >= 300 || decodeErr != nil || !result.Success) {
			return errors.New("Cloudflare TXT cleanup rejected; check token permissions")
		}
		if _, e = a.db.Exec(ctx, "DELETE FROM dns_challenges WHERE id=$1", i.id); e != nil {
			return e
		}
	}
	return nil
}
