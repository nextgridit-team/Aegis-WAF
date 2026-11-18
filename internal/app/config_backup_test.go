package app

// Configuration export/import tests. The restore drill is the acceptance
// test for issue #53: a bundle exported from a configured deployment is
// imported into an isolated empty deployment and the WAF must serve the same
// protection — same routes, same compiled rule counts, same allow/block
// decisions. Everything here fails on main (GET /api/config-export 404s).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func drillLogin(t *testing.T, c *testAPI, cfg Config, username, password string) {
	t.Helper()
	c.call("POST", "/api/setup", map[string]string{"username": username, "password": password, "secret": cfg.BootstrapSecret}, 201)
	data := c.call("POST", "/api/login", map[string]string{"username": username, "password": password}, 200)
	var login map[string]string
	if e := json.Unmarshal(data, &login); e != nil {
		t.Fatal(e)
	}
	c.csrf = login["csrf"]
}

func countRows(t *testing.T, a *App, table string) int {
	t.Helper()
	var n int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

func compiledRuleTotal(a *App) int {
	s := a.active.Load()
	if s == nil {
		return -1
	}
	total := 0
	for _, rules := range s.rules {
		total += len(rules)
	}
	for _, bindings := range s.policyBindings {
		for _, binding := range bindings {
			total += len(binding.Rules)
		}
	}
	return total
}

// TestConfigExportImportRestoreDrill is the documented restore drill: export a
// configured deployment, import the bundle into a fresh database, and prove
// the restored WAF serves the same protection.
func TestConfigExportImportRestoreDrill(t *testing.T) {
	cfgA := testDB(t)
	a := newTestReplica(t, cfgA)
	serverA := httptest.NewServer(a.Management())
	defer serverA.Close()
	jarA, _ := cookiejar.New(nil)
	clientA := &http.Client{Jar: jarA, Timeout: 10 * time.Second}
	c := testAPI{t, clientA, serverA.URL, ""}
	drillLogin(t, &c, cfgA, "admin", "export import drill password")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		io.WriteString(w, "application response")
	}))
	defer upstream.Close()

	// The certificate is uploaded with a private key: the drill proves the
	// key is sealed on the way in and absent from the export on the way out.
	now := time.Now()
	chain, key := testCertificate(t, []string{"drill.example.com"}, 300, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	certID := mustID(t, c.call("POST", "/api/certificates", map[string]string{"name": "Drill TLS", "chain_pem": chain, "private_key_pem": key}, 200))
	siteID := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Drill app", "hostnames": []string{"drill.example.com"}, "upstream": upstream.URL, "certificate_id": certID, "redirect_https": false, "enabled": true}, 200))

	// Address object + group: policy network access references the group, so
	// the import must remap its ID onto the recreated group.
	objectID := mustID(t, c.call("POST", "/api/address-objects", map[string]any{"name": "office", "description": "drill office network", "value": "203.0.113.0/24"}, 200))
	groupID := mustID(t, c.call("POST", "/api/address-groups", map[string]any{"name": "blocked networks", "description": "drill group", "object_ids": []int64{objectID}}, 200))

	// A custom rule blocking one path, both activated natively and selected
	// by a policy group, assigned as the site default.
	spec := probeRule("path", "", "equals", "/forbidden")
	spec.Scope.SiteID = siteID
	ruleID := mustID(t, c.call("POST", "/api/rules", spec, 200))
	c.call("POST", fmt.Sprintf("/api/rules/%d/activate", ruleID), map[string]any{"action": "block", "ttl_seconds": 3600}, 200)
	c.call("POST", "/api/policies", map[string]any{
		"spec": map[string]any{
			"name": "Drill policy", "description": "restore drill", "mode": "block",
			"requests_per_second": 50, "burst": 100, "site_requests_per_second": 500, "site_burst": 1000,
			"network_access": map[string]any{"block_addresses": map[string]any{"group_ids": []int64{groupID}}},
			"groups":         []map[string]any{{"name": "blocked paths", "path_prefix": "/", "methods": []string{"GET", "POST"}, "rule_ids": []int64{ruleID}}},
		},
		"applications": []map[string]any{{"site_id": siteID, "source_cidrs": []string{}, "priority": 10000}},
	}, 200)

	// Alert rule wired to a notification destination: the channel payload is
	// sealed, so restore links destinations by name only.
	channelID := mustID(t, c.call("POST", "/api/notification-channels", map[string]any{"name": "ops webhook", "provider": "webhook", "enabled": true, "config": map[string]any{"url": "https://example.com/hook"}}, 200))
	c.call("POST", "/api/alert-rules", map[string]any{"name": "drill blocked volume", "enabled": true, "kind": "blocked_volume", "site_id": siteID, "threshold": 100, "window_minutes": 5, "cooldown_minutes": 30, "channel_ids": []int64{channelID}}, 200)
	c.call("PUT", "/api/log-settings", map[string]any{"retention_hours": 12, "audit_retention_hours": 24, "revision": 1}, 200)

	ctx := context.Background()
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	probe := func(replica *App, target string) (int, string) {
		r := httptest.NewRequest("GET", "http://drill.example.com"+target, nil)
		w := httptest.NewRecorder()
		replica.Public(w, r)
		return w.Code, w.Body.String()
	}
	if code, body := probe(a, "/safe"); code != 202 || body != "application response" {
		t.Fatalf("source deployment does not proxy: %d %s", code, body)
	}
	if code, _ := probe(a, "/forbidden"); code != 403 {
		t.Fatalf("source deployment does not block: %d", code)
	}

	// EXPORT — the surface this feature adds (404 on main).
	exported := c.call("GET", "/api/config-export", nil, 200)
	var bundle configBundle
	if e := json.Unmarshal(exported, &bundle); e != nil {
		t.Fatal(e)
	}
	if bundle.BundleVersion != configBundleVersion {
		t.Fatalf("bundle version %d", bundle.BundleVersion)
	}
	if bundle.Secrets != "excluded" {
		t.Fatal("bundle must state its secrets policy")
	}
	// No secret material may leave the deployment.
	for _, banned := range []string{"PRIVATE KEY", "key_cipher", "config_cipher", "secret_cipher", "token_hash", "password_hash", "key_id"} {
		if bytes.Contains(exported, []byte(banned)) {
			t.Fatalf("export leaked %q", banned)
		}
	}
	if bytes.Contains(exported, []byte(key)) {
		t.Fatal("export contains the private key PEM")
	}
	if len(bundle.Certificates) != 1 || bundle.Certificates[0].ChainPEM != chain {
		t.Fatalf("public chain missing from bundle: %+v", bundle.Certificates)
	}
	if len(bundle.Sites) != 1 || len(bundle.Rules) != 1 || len(bundle.AddressObjects) != 1 || len(bundle.AddressGroups) != 1 {
		t.Fatalf("bundle sections incomplete: sites=%d rules=%d objects=%d groups=%d", len(bundle.Sites), len(bundle.Rules), len(bundle.AddressObjects), len(bundle.AddressGroups))
	}
	if len(bundle.AlertRules) != 1 || len(bundle.AlertRules[0].Channels) != 1 || bundle.AlertRules[0].Channels[0] != "ops webhook" {
		t.Fatalf("alert rule not exported by channel name: %+v", bundle.AlertRules)
	}
	if bundle.Settings == nil || bundle.Settings.LogRetentionHours == nil || *bundle.Settings.LogRetentionHours != 12 {
		t.Fatalf("log settings missing from bundle: %+v", bundle.Settings)
	}

	// DEPLOYMENT B: a fresh, isolated database.
	cfgB := testDB(t)
	b := newTestReplica(t, cfgB)
	serverB := httptest.NewServer(b.Management())
	defer serverB.Close()
	jarB, _ := cookiejar.New(nil)
	clientB := &http.Client{Jar: jarB, Timeout: 10 * time.Second}
	d := testAPI{t, clientB, serverB.URL, ""}
	drillLogin(t, &d, cfgB, "admin", "restore drill password")
	// Pre-create the notification destination so the alert rule can re-link
	// by name; its payload is deliberately never portable.
	d.call("POST", "/api/notification-channels", map[string]any{"name": "ops webhook", "provider": "webhook", "enabled": true, "config": map[string]any{"url": "https://example.com/hook"}}, 200)

	if n := countRows(t, b, "sites"); n != 0 {
		t.Fatalf("fresh deployment has %d sites", n)
	}

	// DRY RUN: the diff reports the plan and mutates nothing.
	var report importReport
	data := d.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": true}, 200)
	if e := json.Unmarshal(data, &report); e != nil {
		t.Fatal(e)
	}
	if !report.DryRun {
		t.Fatal("dry run not reported")
	}
	if report.Summary["sites"][0] != 1 || report.Summary["rules"][0] != 1 || report.Summary["address_objects"][0] != 1 {
		t.Fatalf("dry-run diff wrong: %+v", report.Summary)
	}
	for _, table := range []string{"sites", "rules", "certificates", "address_objects", "address_groups", "alert_rules"} {
		if n := countRows(t, b, table); n != 0 {
			t.Fatalf("dry run mutated %s (%d rows)", table, n)
		}
	}

	// APPLY.
	data = d.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 200)
	if e := json.Unmarshal(data, &report); e != nil {
		t.Fatal(e)
	}
	if report.DryRun {
		t.Fatal("apply reported as dry run")
	}

	// Round trip: exported semantics exist on the target with local IDs.
	var restoredChain string
	var restoredKey []byte
	if e := b.db.QueryRow(ctx, "SELECT chain_pem,key_cipher FROM certificates WHERE name='Drill TLS'").Scan(&restoredChain, &restoredKey); e != nil {
		t.Fatalf("certificate not restored: %v", e)
	}
	if restoredChain != chain {
		t.Fatal("restored public chain differs")
	}
	if restoredKey != nil {
		t.Fatal("imported certificate carries key material")
	}
	var upstreamURL, hostname string
	if e := b.db.QueryRow(ctx, "SELECT s.upstream,h.hostname FROM sites s JOIN site_hosts h ON h.site_id=s.id WHERE s.name='Drill app'").Scan(&upstreamURL, &hostname); e != nil {
		t.Fatalf("site not restored: %v", e)
	}
	if upstreamURL != upstream.URL || hostname != "drill.example.com" {
		t.Fatalf("restored site differs: %s %s", upstreamURL, hostname)
	}
	var blockedGroup []int64
	if e := b.db.QueryRow(ctx, "SELECT object_ids FROM address_groups WHERE name='blocked networks'").Scan(&blockedGroup); e != nil {
		t.Fatalf("address group not restored: %v", e)
	}
	if len(blockedGroup) != 1 {
		t.Fatalf("restored group has %d objects", len(blockedGroup))
	}
	var restoredPolicySpec []byte
	var restoredAssignments int
	if e := b.db.QueryRow(ctx, "SELECT spec,(SELECT count(*) FROM policy_assignments pa JOIN sites s ON s.id=pa.site_id WHERE pa.policy_id=policies.id AND s.name='Drill app') FROM policies WHERE spec->>'name'='Drill policy'").Scan(&restoredPolicySpec, &restoredAssignments); e != nil {
		t.Fatalf("policy not restored: %v", e)
	}
	var restoredSpec policySpec
	if e := json.Unmarshal(restoredPolicySpec, &restoredSpec); e != nil {
		t.Fatal(e)
	}
	if len(restoredSpec.Groups) != 1 || len(restoredSpec.Groups[0].Rules) != 1 || restoredSpec.NetworkAccess.BlockAddresses.GroupIDs[0] != blockedGroup[0] {
		t.Fatalf("restored policy spec incomplete: %+v", restoredSpec)
	}
	if restoredAssignments != 1 {
		t.Fatalf("policy assignment not restored: %d", restoredAssignments)
	}
	var channelCount int
	if e := b.db.QueryRow(ctx, "SELECT count(*) FROM alert_rules ar JOIN notification_channels nc ON nc.id=ANY(ar.channel_ids) WHERE ar.spec->>'name'='drill blocked volume' AND nc.name='ops webhook'").Scan(&channelCount); e != nil {
		t.Fatalf("alert rule channel link invalid: %v", e)
	}
	if channelCount != 1 {
		t.Fatalf("alert rule not linked to the pre-created destination: %d", channelCount)
	}
	var retention int
	if e := b.db.QueryRow(ctx, "SELECT retention_hours FROM log_settings WHERE id").Scan(&retention); e != nil || retention != 12 {
		t.Fatalf("log settings not restored: %d %v", retention, e)
	}

	// THE DRILL: policies compile on the fresh deployment (refresh runs the
	// full load-path validation) and the WAF serves the same protection.
	if e := b.refresh(ctx); e != nil {
		t.Fatalf("restored configuration does not load: %v", e)
	}
	if code, body := probe(b, "/safe"); code != 202 || body != "application response" {
		t.Fatalf("restored deployment does not proxy identically: %d %s", code, body)
	}
	if code, _ := probe(b, "/forbidden"); code != 403 {
		t.Fatalf("restored deployment does not block identically: %d", code)
	}
	if total := compiledRuleTotal(a); total < 1 {
		t.Fatalf("source engine counts invalid: %d", total)
	}
	if totalA, totalB := compiledRuleTotal(a), compiledRuleTotal(b); totalA != totalB {
		t.Fatalf("engine counts differ after restore: source %d restored %d", totalA, totalB)
	}
	if count := countRows(t, b, "sites"); count != 1 {
		t.Fatalf("restored site count %d", count)
	}
}

// TestConfigImportRejectsUnknownVersion proves the schema guard: bundles from
// unknown or newer versions are refused with a clear error.
func TestConfigImportRejectsUnknownVersion(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "version guard password")
	bundle := configBundle{BundleVersion: configBundleVersion + 1, Secrets: "excluded", SchemaVersion: 1}
	data := c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": true}, 400)
	if !bytes.Contains(data, []byte("unsupported bundle version 2")) {
		t.Fatalf("missing version error: %s", data)
	}
	// A newer database schema in the bundle is equally refused.
	bundle = configBundle{BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 9999}
	data = c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": true}, 400)
	if !bytes.Contains(data, []byte("upgrade this deployment before importing")) {
		t.Fatalf("missing schema error: %s", data)
	}
}

// TestConfigImportTransactional proves one transaction: a bundle whose last
// section fails validation leaves the database unchanged.
func TestConfigImportTransactional(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "transactional import password")
	good := exportSite{Name: "Transaction app", Hostnames: []string{"txn.example.com"}, Upstream: "http://127.0.0.1:8080", Enabled: true}
	bundle := configBundle{
		BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1,
		Sites: []exportSite{good},
		// Valid shape, invalid policy mode: fails only after the site write.
		Policies: []exportPolicy{{Spec: json.RawMessage(`{"name":"broken","mode":"sideways"}`), Revisions: []exportPolicyRevision{}}},
	}
	data := c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 400)
	if !bytes.Contains(data, []byte("mode must be off, observe or block")) {
		t.Fatalf("expected policy validation error, got %s", data)
	}
	if n := countRows(t, a, "sites"); n != 0 {
		t.Fatalf("failed import left %d sites behind", n)
	}
	// The same bundle without the broken policy applies.
	bundle.Policies = nil
	c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 200)
	if n := countRows(t, a, "sites"); n != 1 {
		t.Fatalf("valid import did not apply: %d sites", n)
	}
	// A crafted bundle cannot bypass validation with unknown fields.
	data = c.call("POST", "/api/config-import", map[string]any{"bundle": map[string]any{"bundle_version": configBundleVersion, "secrets": "excluded", "schema_version": 1, "sites": []map[string]any{{"name": "smuggled", "hostnames": []string{"smuggle.example.com"}, "upstream": "http://127.0.0.1:8080", "enabled": true, "execute": "forbidden"}}}, "dry_run": false}, 400)
	if !bytes.Contains(data, []byte("invalid JSON request")) {
		t.Fatalf("unknown fields were accepted: %s", data)
	}
	if n := countRows(t, a, "sites"); n != 1 {
		t.Fatalf("smuggled site count %d", n)
	}
}

// TestConfigExportRequiresSession proves the bundle surface is restricted to
// administrator sessions and stays outside the agent operation catalog.
func TestConfigExportRequiresSession(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	r, _ := http.NewRequest("GET", server.URL+"/api/config-export", nil)
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("unauthenticated export returned %d", res.StatusCode)
	}
	for _, op := range agentOperations() {
		if strings.Contains(op.Pattern, "config-export") || strings.Contains(op.Pattern, "config-import") {
			t.Fatalf("bundle route exposed to agent keys: %s", op.Pattern)
		}
	}
}

// A restored site whose certificate carries no key material must not keep
// HTTPS redirect: it would 308 visitors into an SNI that cannot complete a
// handshake. The import forces the redirect off and says so in the report.
func TestConfigImportForcesPlainHTTPForKeylessCerts(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "keyless redirect password")
	now := time.Now()
	chain, _ := testCertificate(t, []string{"keyless.example.com"}, 300, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	audit := 720
	retention := 336
	bundle := configBundle{
		BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1,
		Certificates: []exportCertificate{{Name: "Keyless TLS", Origin: "upload", Domains: []string{"keyless.example.com"}, ChainPEM: chain, ChallengeType: "http-01"}},
		Sites:        []exportSite{{Name: "Keyless app", Hostnames: []string{"keyless.example.com"}, Upstream: "http://127.0.0.1:8080", Certificate: "Keyless TLS", RedirectHTTPS: true, Enabled: true}},
		Settings:     &exportSettings{LogRetentionHours: &retention, AuditRetentionHours: &audit},
	}
	data := c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 200)
	if !bytes.Contains(data, []byte("HTTPS redirect disabled")) {
		t.Fatalf("import report missing the forced-plain warning: %s", data)
	}
	var redirect bool
	if e := a.db.QueryRow(context.Background(), "SELECT redirect_https FROM sites WHERE name='Keyless app'").Scan(&redirect); e != nil || redirect {
		t.Fatalf("keyless cert site kept redirect_https=%v (%v)", redirect, e)
	}
}

// Import enforces the same log-settings floor the dashboard API enforces:
// the audit window may never fall below the traffic-log window.
func TestConfigImportEnforcesAuditFloor(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "audit floor password")
	retention, audit := 200, 1
	bundle := configBundle{BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1, Settings: &exportSettings{LogRetentionHours: &retention, AuditRetentionHours: &audit}}
	data := c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 400)
	if !bytes.Contains(data, []byte("audit_retention_hours must be at least")) {
		t.Fatalf("audit floor not enforced: %s", data)
	}
}

// The AI provider import must upsert like the dashboard API: a fresh
// deployment has no seeded row, and a bare UPDATE would silently lose the
// restored endpoint and model while the report claims success.
func TestConfigImportUpsertsAIProvider(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "ai upsert password")
	bundle := configBundle{BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1, Settings: &exportSettings{AIProvider: &exportAIProvider{BaseURL: "https://api.example.com/v1", Model: "test-model"}}}
	c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 200)
	var baseURL, model string
	var keyCipher []byte
	if e := a.db.QueryRow(context.Background(), "SELECT base_url,model,key_cipher FROM ai_provider WHERE id").Scan(&baseURL, &model, &keyCipher); e != nil {
		t.Fatalf("ai_provider not restored: %v", e)
	}
	if baseURL != "https://api.example.com/v1" || model != "test-model" {
		t.Fatalf("ai_provider restored wrong values: %s %s", baseURL, model)
	}
	if len(keyCipher) != 0 {
		t.Fatal("ai_provider must restore without a key")
	}
}

// The import persists re-marshaled validated traffic settings, so a crafted
// bundle cannot smuggle keys the dashboard API itself refuses to write.
func TestConfigImportReMarshalsTrafficSettings(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "traffic re-marshal password")
	smuggled := json.RawMessage(`{"query_keys":[],"header_keys":[],"json_body_keys":[],"sample_every":1,"max_per_minute":60,"retention_hours":24,"pr66_smuggled_key":true}`)
	bundle := configBundle{
		BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1,
		Sites: []exportSite{{Name: "Smuggle app", Hostnames: []string{"smuggle.example.com"}, Upstream: "http://127.0.0.1:8080", Enabled: true, Traffic: smuggled}},
	}
	c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 200)
	var settings []byte
	if e := a.db.QueryRow(context.Background(), "SELECT settings FROM traffic_settings ts JOIN sites s ON s.id=ts.site_id WHERE s.name='Smuggle app'").Scan(&settings); e != nil {
		t.Fatalf("traffic settings not stored: %v", e)
	}
	if bytes.Contains(settings, []byte("pr66_smuggled_key")) {
		t.Fatalf("smuggled traffic key persisted: %s", settings)
	}
}

// A crafted bundle cannot exceed the address inventory caps the dashboard
// API enforces (1024 objects, 128 groups).
func TestConfigImportEnforcesAddressCaps(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	drillLogin(t, &c, cfg, "admin", "address caps password")
	objects := make([]exportAddressObject, 1026)
	for i := range objects {
		objects[i] = exportAddressObject{Name: fmt.Sprintf("obj-%d", i), Value: "203.0.113.1"}
	}
	bundle := configBundle{BundleVersion: configBundleVersion, Secrets: "excluded", SchemaVersion: 1, AddressObjects: objects}
	data := c.call("POST", "/api/config-import", map[string]any{"bundle": bundle, "dry_run": false}, 400)
	if !bytes.Contains(data, []byte("address inventory capacity reached")) {
		t.Fatalf("address cap not enforced: %s", data)
	}
	if n := countRows(t, a, "address_objects"); n != 0 {
		t.Fatalf("over-cap import left %d objects behind", n)
	}
}

// A certificate that loses its sealed key material must not be skipped
// silently: config load logs a warning naming the count. This guards the
// ordering bug the re-review caught (a count issued between tx.Query and
// the rows drain fails with "conn busy" and the warning never fires).
func TestConfigLoadWarnsOnKeylessCertificates(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	captured := []string{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&sliceWriter{&captured}, nil)))
	defer slog.SetDefault(previous)
	// Seed a certificate with key material, then corrupt its seal, bump the
	// version, and refresh — the warning must fire.
	if _, e := a.db.Exec(ctx, "INSERT INTO certificates(name,origin,domains,chain_pem,key_cipher,key_id) VALUES('Corrupted seal','upload',ARRAY['corrupt.test'],'chain',decode('00','hex'),'key')"); e != nil {
		t.Fatal(e)
	}
	if _, e := a.db.Exec(ctx, "UPDATE certificates SET key_cipher=NULL,key_id=NULL WHERE name='Corrupted seal'"); e != nil {
		t.Fatal(e)
	}
	if _, e := a.db.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id"); e != nil {
		t.Fatal(e)
	}
	if e := a.refresh(ctx); e != nil {
		t.Fatalf("refresh with keyless cert: %v", e)
	}
	joined := strings.Join(captured, "\n")
	if !strings.Contains(joined, "skipping certificate(s) without sealed key material") {
		t.Fatalf("config load did not warn about the keyless certificate; captured: %q", joined)
	}
}

type sliceWriter struct{ lines *[]string }

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.lines = append(*w.lines, string(p))
	return len(p), nil
}
