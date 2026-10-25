package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type feedDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Rules         []feedCandidate `json:"rules"`
}
type feedCandidate struct {
	ID   string   `json:"id"`
	Rule RuleSpec `json:"rule"`
}

// Rule feeds are public HTTPS documents. Do not permit credentials, nonstandard
// ports, redirects, private targets or proxy-environment bypasses of these checks.
func feedURL(raw string) (*url.URL, error) {
	if len(raw) > 2048 {
		return nil, invalid("feed URL is too long")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, invalid("provide a public HTTPS URL without credentials, query parameters or a nonstandard port")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !feedPublicIP(ip) {
		return nil, invalid("feed URL must use a public address")
	}
	return u, nil
}
func feedPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48", "::/96"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}
func feedTransport() *http.Transport {
	return &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("feed host lookup failed")
		}
		for _, ip := range ips {
			if !feedPublicIP(ip) {
				return nil, errors.New("feed host resolves to a non-public address")
			}
		}
		var last error
		dialer := net.Dialer{Timeout: 5 * time.Second}
		for _, ip := range ips {
			var c net.Conn
			c, last = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if last == nil {
				return c, nil
			}
		}
		return nil, last
	}}
}
func parseFeed(raw []byte, site int64) (feedDocument, error) {
	var doc feedDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&doc); e != nil {
		return doc, invalid("feed is not a supported JSON rule document")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return doc, invalid("feed must contain one JSON document")
	}
	if doc.SchemaVersion != 1 || doc.Rules == nil || len(doc.Rules) > 100 {
		return doc, invalid("feed schema_version must be 1 and rules must contain at most 100 entries")
	}
	seen := map[string]bool{}
	for n := range doc.Rules {
		item := &doc.Rules[n]
		if len(item.ID) < 1 || len(item.ID) > 64 || !namedKey.MatchString(item.ID) || seen[item.ID] {
			return doc, invalid("feed rule IDs must be unique names of 1–64 letters, numbers, dots, underscores or hyphens")
		}
		seen[item.ID] = true
		item.Rule.Scope.SiteID = site
		item.Rule.Action = "observe"
		item.Rule.EvidenceIDs = nil
		if _, e := compileRule(item.Rule); e != nil {
			return doc, invalid("feed contains an invalid rule: " + e.Error())
		}
	}
	return doc, nil
}
func (a *App) fetchFeed(ctx context.Context, rawURL, etag string, site int64) (feedDocument, string, bool, error) {
	var doc feedDocument
	parsed, e := feedURL(rawURL)
	if e != nil {
		return doc, "", false, e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if e != nil {
		return doc, "", false, invalid("invalid feed URL")
	}
	req.Header.Set("Accept", "application/json")
	if parsed.Hostname() == "api.github.com" && strings.HasPrefix(parsed.Path, "/repos/") && strings.Contains(parsed.Path, "/contents/") {
		req.Header.Set("Accept", "application/vnd.github.raw+json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	transport := a.feedHTTP
	if transport == nil {
		transport = feedTransport()
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return doc, "", false, apiError{502, "feed download failed; check public DNS, HTTPS reachability and certificate trust"}
	}
	defer response.Body.Close()
	if response.StatusCode == 304 && etag != "" {
		return doc, etag, true, nil
	}
	if response.StatusCode != 200 {
		return doc, "", false, apiError{502, "feed server returned HTTP " + strconv.Itoa(response.StatusCode)}
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return doc, "", false, invalid("feed exceeds 1 MiB or could not be read")
	}
	doc, e = parseFeed(raw, site)
	if e != nil {
		return doc, "", false, e
	}
	nextETag := response.Header.Get("ETag")
	if len(nextETag) > 256 {
		nextETag = ""
	}
	return doc, nextETag, false, nil
}
func (a *App) syncFeed(ctx context.Context, id int64, manual bool, actor string) error {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	conn, e := a.db.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var locked bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(700020,$1::int)", id).Scan(&locked); e != nil {
		return e
	}
	if !locked {
		return apiError{409, "this feed is already syncing"}
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, e := conn.Exec(unlock, "SELECT pg_advisory_unlock(700020,$1::int)", id); e != nil {
			conn.Conn().Close(unlock)
		}
	}()
	var rawURL, etag string
	var site int64
	var due bool
	e = conn.QueryRow(ctx, "SELECT url,etag,site_id,next_sync<=now() FROM rule_feeds WHERE id=$1", id).Scan(&rawURL, &etag, &site, &due)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{404, "feed not found"}
	}
	if e != nil {
		return e
	}
	if !manual && !due {
		return nil
	}
	doc, nextETag, unchanged, fetchErr := a.fetchFeed(ctx, rawURL, etag, site)
	if fetchErr != nil {
		_, e = conn.Exec(ctx, "UPDATE rule_feeds SET last_attempt=now(),next_sync=now()+interval '12 hours',error=$2 WHERE id=$1", id, fetchErr.Error())
		if e != nil {
			return e
		}
		return fetchErr
	}
	tx, e := conn.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// Lock the source before candidate mutations; a removed source cannot reappear.
	var existing int64
	if e = tx.QueryRow(ctx, "SELECT id FROM rule_feeds WHERE id=$1 FOR UPDATE", id).Scan(&existing); e != nil {
		return e
	}
	if !unchanged {
		if _, e = tx.Exec(ctx, "UPDATE rule_feed_items SET available=false WHERE feed_id=$1", id); e != nil {
			return e
		}
		for _, item := range doc.Rules {
			raw, _ := json.Marshal(item.Rule)
			if _, e = tx.Exec(ctx, "INSERT INTO rule_feed_items(feed_id,entry_id,spec) VALUES($1,$2,$3) ON CONFLICT(feed_id,entry_id) DO UPDATE SET spec=excluded.spec,available=true", id, item.ID, raw); e != nil {
				return e
			}
		}
	}
	if _, e = tx.Exec(ctx, "UPDATE rule_feeds SET last_attempt=now(),last_success=now(),next_sync=now()+interval '12 hours',error='',etag=$2 WHERE id=$1", id, nextETag); e != nil {
		return e
	}
	if e = audit(ctx, tx, actor, "feed.synced", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *App) FeedWorker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.initialized.Load() {
				continue
			}
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			rows, e := a.db.Query(c, "SELECT id FROM rule_feeds WHERE next_sync<=now() ORDER BY next_sync LIMIT 20")
			ids := []int64{}
			if e == nil {
				for rows.Next() {
					var id int64
					if rows.Scan(&id) == nil {
						ids = append(ids, id)
					}
				}
				rows.Close()
			}
			cancel()
			for _, id := range ids {
				if ctx.Err() != nil {
					return
				}
				_ = a.syncFeed(ctx, id, false, "scheduler")
			}
		}
	}
}
func (a *App) createFeed(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		SiteID int64  `json:"site_id"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Name = strings.TrimSpace(body.Name)
	if len(body.Name) < 1 || len(body.Name) > 120 {
		return invalid("provide a feed name of 1–120 bytes")
	}
	if _, e := feedURL(body.URL); e != nil {
		return e
	}
	var id int64
	e := a.change(r.Context(), func(tx pgx.Tx) error {
		var total int
		if e := tx.QueryRow(r.Context(), "SELECT count(*) FROM rule_feeds").Scan(&total); e != nil {
			return e
		}
		if total >= 20 {
			return apiError{409, "at most 20 rule feeds are supported"}
		}
		var exists bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", body.SiteID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return invalid("choose an existing application")
		}
		if e := tx.QueryRow(r.Context(), "INSERT INTO rule_feeds(name,url,site_id) VALUES($1,$2,$3) RETURNING id", body.Name, body.URL, body.SiteID).Scan(&id); e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "feed.created", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 201, map[string]int64{"id": id})
	return nil
}
func (a *App) importFeed(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	imported := []int64{}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		var site int64
		e := tx.QueryRow(ctx, "SELECT site_id FROM rule_feeds WHERE id=$1 FOR UPDATE", id).Scan(&site)
		if errors.Is(e, pgx.ErrNoRows) {
			return apiError{404, "feed not found"}
		}
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, "SELECT entry_id,spec FROM rule_feed_items WHERE feed_id=$1 AND available AND spec IS DISTINCT FROM imported_spec ORDER BY entry_id", id)
		if e != nil {
			return e
		}
		items := []feedCandidate{}
		for rows.Next() {
			var entry string
			var raw []byte
			if e = rows.Scan(&entry, &raw); e != nil {
				rows.Close()
				return e
			}
			var spec RuleSpec
			if e = json.Unmarshal(raw, &spec); e != nil {
				rows.Close()
				return e
			}
			items = append(items, feedCandidate{entry, spec})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, item := range items {
			item.Rule.Scope.SiteID = site
			item.Rule.Action = "observe"
			if _, e = compileRule(item.Rule); e != nil {
				return e
			}
			if e = checkRuleSite(ctx, tx, site, 0); e != nil {
				return e
			}
			raw, _ := json.Marshal(item.Rule)
			var rule int64
			if e = tx.QueryRow(ctx, "INSERT INTO rules(site_id,spec) VALUES($1,$2) RETURNING id", site, raw).Scan(&rule); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "UPDATE rule_feed_items SET imported_spec=spec,rule_id=$3 WHERE feed_id=$1 AND entry_id=$2", id, item.ID, rule); e != nil {
				return e
			}
			if e = ruleHistory(ctx, tx, rule, i.Username); e != nil {
				return e
			}
			imported = append(imported, rule)
		}
		return audit(ctx, tx, i.Username, "feed.imported_drafts", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]any{"rule_ids": imported, "enabled": false})
	return nil
}
func feedAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/rule-feeds", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, `SELECT f.id,f.name,f.url,f.site_id,f.last_attempt,f.last_success,f.next_sync,f.error,(SELECT count(*) FROM rule_feed_items i WHERE i.feed_id=f.id AND i.available) AS candidates,(SELECT count(*) FROM rule_feed_items i WHERE i.feed_id=f.id AND i.available AND i.spec IS DISTINCT FROM i.imported_spec) AS pending FROM rule_feeds f ORDER BY f.id`)
	}))
	m.HandleFunc("POST /api/rule-feeds", a.wrap(true, a.createFeed))
	m.HandleFunc("GET /api/rule-feeds/{id}/items", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		return a.list(w, r, "SELECT entry_id,spec,available,rule_id,spec IS DISTINCT FROM imported_spec AS pending FROM rule_feed_items WHERE feed_id="+strconv.FormatInt(id, 10)+" ORDER BY entry_id")
	}))
	m.HandleFunc("POST /api/rule-feeds/{id}/sync", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		if e = a.syncFeed(r.Context(), id, true, i.Username); e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"synced": true})
		return nil
	}))
	m.HandleFunc("POST /api/rule-feeds/{id}/import", a.wrap(true, a.importFeed))
	m.HandleFunc("DELETE /api/rule-feeds/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			tag, e := tx.Exec(r.Context(), "DELETE FROM rule_feeds WHERE id=$1", id)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 0 {
				return apiError{404, "feed not found"}
			}
			return audit(r.Context(), tx, i.Username, "feed.deleted", strconv.FormatInt(id, 10))
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"deleted": true})
		return nil
	}))
}
