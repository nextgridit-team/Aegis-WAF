package app

// Configuration export/import with a tested restore path. The bundle is a
// portable, secret-free projection of deployment configuration: sites, public
// certificate chains, policies with revisions and assignments, custom rules,
// curated set references, rule feed selections, address objects and groups,
// per-site headers/protection/traffic settings, alert rules and the non-secret
// global settings. Private keys, ACME account keys, DNS credentials, provider
// credentials, notification channel payloads, rate-state passwords, agent key
// material, administrator rows and runtime state are never part of a bundle;
// the format states this in `secrets`.
//
// Import reuses the same validators the dashboard API applies (the normalize*
// and validate* helpers named per section below) so a crafted bundle cannot
// bypass validation, and it applies inside a single transaction guarded by
// config_version's write lock: a failure anywhere rolls the whole import back.
// The dry run executes the identical code path and rolls back instead of
// committing, so the reported diff is exactly the diff an apply would run.
//
// The bundle routes are deliberately absent from the MCP operation catalog:
// a bundle carries hostnames, policy shapes and address objects, so it is
// restricted to administrator sessions (issue #53's ownership note).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	configBundleVersion   = 1
	configBundleSecrets   = "excluded"
	configImportBodyLimit = 32 << 20
)

type configBundle struct {
	BundleVersion int    `json:"bundle_version"`
	SchemaVersion int    `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Secrets       string `json:"secrets"`

	AddressObjects []exportAddressObject `json:"address_objects"`
	AddressGroups  []exportAddressGroup  `json:"address_groups"`
	Certificates   []exportCertificate   `json:"certificates"`
	SignatureSets  []exportSignatureSet  `json:"signature_sets"`
	Sites          []exportSite          `json:"sites"`
	Rules          []exportRule          `json:"rules"`
	Policies       []exportPolicy        `json:"policies"`
	RuleFeeds      []exportRuleFeed      `json:"rule_feeds"`
	AlertRules     []exportAlertRule     `json:"alert_rules"`
	Settings       *exportSettings       `json:"settings"`
}

type exportAddressObject struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Value       string `json:"value"`
	IsLocal     bool   `json:"is_local"`
}

type exportAddressGroup struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Objects     []string `json:"objects"`
}

type exportCertificate struct {
	Name            string     `json:"name"`
	Origin          string     `json:"origin"`
	Domains         []string   `json:"domains"`
	ChainPEM        string     `json:"chain_pem"`
	Issuer          string     `json:"issuer"`
	NotBefore       *time.Time `json:"not_before"`
	NotAfter        *time.Time `json:"not_after"`
	ChallengeType   string     `json:"challenge_type"`
	RenewBeforeDays *int       `json:"renew_before_days"`
}

type exportSignatureSet struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Digest    string `json:"digest"`
	RuleCount int    `json:"rule_count"`
}

type exportSite struct {
	Name           string          `json:"name"`
	Hostnames      []string        `json:"hostnames"`
	Upstream       string          `json:"upstream"`
	Certificate    string          `json:"certificate"`
	RedirectHTTPS  bool            `json:"redirect_https"`
	PreserveHost   bool            `json:"preserve_host"`
	Enabled        bool            `json:"enabled"`
	TrafficProfile string          `json:"traffic_profile"`
	StreamWindow   int             `json:"stream_window_bytes"`
	UpstreamTLS    json.RawMessage `json:"upstream_tls"`
	BlockTitle     string          `json:"block_title"`
	BlockContact   string          `json:"block_contact"`
	BlockReference string          `json:"block_reference"`
	Headers        json.RawMessage `json:"headers"`
	Protection     json.RawMessage `json:"protection"`
	Traffic        json.RawMessage `json:"traffic"`
}

// exportRule carries the source rule ID so policy specs (which reference rules
// by ID) can be remapped onto the IDs the import creates.
type exportRule struct {
	ID        int64           `json:"id"`
	Site      string          `json:"site"`
	Spec      json.RawMessage `json:"spec"`
	Enabled   bool            `json:"enabled"`
	ExpiresAt *time.Time      `json:"expires_at"`
}

type exportPolicyAssignment struct {
	Site        string   `json:"site"`
	SourceCIDRs []string `json:"source_cidrs"`
	Priority    int      `json:"priority"`
}

type exportPolicyRevision struct {
	Revision int64           `json:"revision"`
	Spec     json.RawMessage `json:"spec"`
	Actor    string          `json:"actor"`
	At       time.Time       `json:"at"`
}

type exportPolicy struct {
	Spec        json.RawMessage          `json:"spec"`
	Revision    int64                    `json:"revision"`
	BuiltIn     string                   `json:"built_in"`
	Assignments []exportPolicyAssignment `json:"assignments"`
	Revisions   []exportPolicyRevision   `json:"revisions"`
}

type exportRuleFeed struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Site    string `json:"site"`
	BuiltIn string `json:"built_in"`
}

type exportAlertRule struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Kind            string   `json:"kind"`
	Site            string   `json:"site"`
	Threshold       int      `json:"threshold"`
	WindowMinutes   int      `json:"window_minutes"`
	CooldownMinutes int      `json:"cooldown_minutes"`
	Channels        []string `json:"channels"`
}

type exportSettings struct {
	LogRetentionHours   *int              `json:"log_retention_hours"`
	AuditRetentionHours *int              `json:"audit_retention_hours"`
	RateState           json.RawMessage   `json:"rate_state"`
	AIProvider          *exportAIProvider `json:"ai_provider"`
	AgentAccessEnabled  *bool             `json:"agent_access_enabled"`
	LocalPublicIP       string            `json:"local_public_ip"`
	GeoSources          []exportGeoSource `json:"geo_sources"`
}

type exportAIProvider struct {
	BaseURL string   `json:"base_url"`
	Model   string   `json:"model"`
	Models  []string `json:"models"`
}

type exportGeoSource struct {
	Kind     string `json:"kind"`
	Enabled  bool   `json:"enabled"`
	AutoSync bool   `json:"auto_sync"`
}

type importChange struct {
	Section string `json:"section"`
	Action  string `json:"action"` // create, update or skip
	Name    string `json:"name"`
	Detail  string `json:"detail,omitempty"`
}

type importReport struct {
	DryRun   bool              `json:"dry_run"`
	Changes  []importChange    `json:"changes"`
	Summary  map[string][3]int `json:"summary"`
	Warnings []string          `json:"warnings,omitempty"`
}

func (rep *importReport) record(section, action, name, detail string) {
	rep.Changes = append(rep.Changes, importChange{Section: section, Action: action, Name: name, Detail: detail})
	counts := rep.Summary[section]
	switch action {
	case "create":
		counts[0]++
	case "update":
		counts[1]++
	case "skip":
		counts[2]++
	}
	rep.Summary[section] = counts
}

func (rep *importReport) warn(message string) {
	rep.Warnings = append(rep.Warnings, message)
}

// present reports whether an exported optional JSON section carries data:
// absent sections marshal to a literal "null" that must be treated as absent.
func present(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return len(trimmed) > 0 && trimmed != "null"
}

// buildConfigBundle reads deployment configuration into a secret-free bundle
// under a repeatable-read snapshot so cross-section references stay coherent.
func (a *App) buildConfigBundle(ctx context.Context) (*configBundle, error) {
	tx, e := a.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	bundle := &configBundle{
		BundleVersion: configBundleVersion,
		Secrets:       configBundleSecrets,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if e = tx.QueryRow(ctx, "SELECT max(version) FROM schema_version").Scan(&bundle.SchemaVersion); e != nil {
		return nil, e
	}
	siteNames, certNames, e := exportNames(ctx, tx)
	if e != nil {
		return nil, e
	}
	if bundle.AddressObjects, e = exportAddressObjects(ctx, tx); e != nil {
		return nil, e
	}
	if bundle.AddressGroups, e = exportAddressGroups(ctx, tx); e != nil {
		return nil, e
	}
	if bundle.Certificates, e = exportCertificates(ctx, tx); e != nil {
		return nil, e
	}
	if bundle.SignatureSets, e = exportSignatureSets(ctx, tx); e != nil {
		return nil, e
	}
	if bundle.Sites, e = exportSites(ctx, tx, certNames); e != nil {
		return nil, e
	}
	if bundle.Rules, e = exportRules(ctx, tx, siteNames); e != nil {
		return nil, e
	}
	if bundle.Policies, e = exportPolicies(ctx, tx, siteNames); e != nil {
		return nil, e
	}
	if bundle.RuleFeeds, e = exportRuleFeeds(ctx, tx, siteNames); e != nil {
		return nil, e
	}
	if bundle.AlertRules, e = exportAlertRules(ctx, tx, siteNames); e != nil {
		return nil, e
	}
	if bundle.Settings, e = exportSettingsSection(ctx, tx); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return bundle, nil
}

func exportNames(ctx context.Context, tx pgx.Tx) (map[int64]string, map[int64]string, error) {
	sites, certs := map[int64]string{}, map[int64]string{}
	for _, pair := range []struct {
		sql  string
		into map[int64]string
	}{{"SELECT id,name FROM sites", sites}, {"SELECT id,name FROM certificates", certs}} {
		rows, e := tx.Query(ctx, pair.sql)
		if e != nil {
			return nil, nil, e
		}
		for rows.Next() {
			var id int64
			var name string
			if e = rows.Scan(&id, &name); e != nil {
				rows.Close()
				return nil, nil, e
			}
			pair.into[id] = name
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, nil, e
		}
	}
	return sites, certs, nil
}

func exportAddressObjects(ctx context.Context, tx pgx.Tx) ([]exportAddressObject, error) {
	rows, e := tx.Query(ctx, "SELECT id,name,description,value,is_local FROM address_objects ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportAddressObject{}
	for rows.Next() {
		var item exportAddressObject
		if e = rows.Scan(&item.ID, &item.Name, &item.Description, &item.Value, &item.IsLocal); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportAddressGroups(ctx context.Context, tx pgx.Tx) ([]exportAddressGroup, error) {
	rows, e := tx.Query(ctx, "SELECT g.id,g.name,g.description,coalesce(array_agg(o.name ORDER BY o.name) FILTER(WHERE o.id IS NOT NULL),'{}') FROM address_groups g LEFT JOIN address_objects o ON o.id=ANY(g.object_ids) GROUP BY g.id,g.name,g.description ORDER BY g.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportAddressGroup{}
	for rows.Next() {
		var item exportAddressGroup
		if e = rows.Scan(&item.ID, &item.Name, &item.Description, &item.Objects); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportCertificates(ctx context.Context, tx pgx.Tx) ([]exportCertificate, error) {
	rows, e := tx.Query(ctx, "SELECT name,origin,domains,chain_pem,issuer,not_before,not_after,challenge_type,renew_before_days FROM certificates ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportCertificate{}
	for rows.Next() {
		var item exportCertificate
		if e = rows.Scan(&item.Name, &item.Origin, &item.Domains, &item.ChainPEM, &item.Issuer, &item.NotBefore, &item.NotAfter, &item.ChallengeType, &item.RenewBeforeDays); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportSignatureSets(ctx context.Context, tx pgx.Tx) ([]exportSignatureSet, error) {
	rows, e := tx.Query(ctx, "SELECT id,name,version,digest,rule_count FROM signature_sets ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportSignatureSet{}
	for rows.Next() {
		var item exportSignatureSet
		if e = rows.Scan(&item.ID, &item.Name, &item.Version, &item.Digest, &item.RuleCount); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportSites(ctx context.Context, tx pgx.Tx, certNames map[int64]string) ([]exportSite, error) {
	rows, e := tx.Query(ctx, "SELECT s.id,s.name,s.hostnames,s.upstream,s.certificate_id,s.redirect_https,s.preserve_host,s.enabled,s.traffic_profile,s.stream_window_bytes,s.upstream_tls,s.block_title,s.block_contact,s.block_reference,p.settings,h.settings,t.settings FROM sites s LEFT JOIN protection_settings p ON p.site_id=s.id LEFT JOIN proxy_headers h ON h.site_id=s.id LEFT JOIN traffic_settings t ON t.site_id=s.id ORDER BY s.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportSite{}
	for rows.Next() {
		var item exportSite
		var id, certID *int64
		var upstreamTLS []byte
		if e = rows.Scan(&id, &item.Name, &item.Hostnames, &item.Upstream, &certID, &item.RedirectHTTPS, &item.PreserveHost, &item.Enabled, &item.TrafficProfile, &item.StreamWindow, &upstreamTLS, &item.BlockTitle, &item.BlockContact, &item.BlockReference, &item.Protection, &item.Headers, &item.Traffic); e != nil {
			return nil, e
		}
		if len(upstreamTLS) > 0 {
			item.UpstreamTLS = append(json.RawMessage{}, upstreamTLS...)
		}
		if certID != nil {
			item.Certificate = certNames[*certID]
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportRules(ctx context.Context, tx pgx.Tx, siteNames map[int64]string) ([]exportRule, error) {
	rows, e := tx.Query(ctx, "SELECT id,site_id,spec,enabled,expires_at FROM rules ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportRule{}
	for rows.Next() {
		var item exportRule
		var site int64
		if e = rows.Scan(&item.ID, &site, &item.Spec, &item.Enabled, &item.ExpiresAt); e != nil {
			return nil, e
		}
		item.Site = siteNames[site]
		item.Spec = append(json.RawMessage{}, item.Spec...)
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportPolicies(ctx context.Context, tx pgx.Tx, siteNames map[int64]string) ([]exportPolicy, error) {
	// Buffer the policy rows before issuing the per-policy history queries:
	// pgx streams result sets, so a second query on the same transaction while
	// the first is open fails with "conn busy".
	type policyRow struct {
		id   int64
		item exportPolicy
	}
	buffer := []policyRow{}
	rows, e := tx.Query(ctx, "SELECT id,spec,revision,coalesce((SELECT key FROM built_in_policies WHERE policy_id=p.id),'') FROM policies p ORDER BY id")
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var row policyRow
		if e = rows.Scan(&row.id, &row.item.Spec, &row.item.Revision, &row.item.BuiltIn); e != nil {
			rows.Close()
			return nil, e
		}
		row.item.Spec = append(json.RawMessage{}, row.item.Spec...)
		buffer = append(buffer, row)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	out := []exportPolicy{}
	for _, row := range buffer {
		item := row.item
		item.Assignments = []exportPolicyAssignment{}
		assign, e := tx.Query(ctx, "SELECT site_id,source_cidrs,priority FROM policy_assignments WHERE policy_id=$1 ORDER BY priority,site_id", row.id)
		if e != nil {
			return nil, e
		}
		for assign.Next() {
			var site int64
			var entry exportPolicyAssignment
			if e = assign.Scan(&site, &entry.SourceCIDRs, &entry.Priority); e != nil {
				assign.Close()
				return nil, e
			}
			entry.Site = siteNames[site]
			item.Assignments = append(item.Assignments, entry)
		}
		assign.Close()
		if e = assign.Err(); e != nil {
			return nil, e
		}
		item.Revisions = []exportPolicyRevision{}
		history, e := tx.Query(ctx, "SELECT revision,spec,actor,at FROM policy_revisions WHERE policy_id=$1 ORDER BY revision", row.id)
		if e != nil {
			return nil, e
		}
		for history.Next() {
			var entry exportPolicyRevision
			if e = history.Scan(&entry.Revision, &entry.Spec, &entry.Actor, &entry.At); e != nil {
				history.Close()
				return nil, e
			}
			entry.Spec = append(json.RawMessage{}, entry.Spec...)
			item.Revisions = append(item.Revisions, entry)
		}
		history.Close()
		if e = history.Err(); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, nil
}

func exportRuleFeeds(ctx context.Context, tx pgx.Tx, siteNames map[int64]string) ([]exportRuleFeed, error) {
	rows, e := tx.Query(ctx, "SELECT f.id,f.name,f.url,coalesce(f.site_id,0),coalesce((SELECT key FROM built_in_rule_feeds WHERE feed_id=f.id),'') FROM rule_feeds f ORDER BY f.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportRuleFeed{}
	for rows.Next() {
		var id, site int64
		var item exportRuleFeed
		if e = rows.Scan(&id, &item.Name, &item.URL, &site, &item.BuiltIn); e != nil {
			return nil, e
		}
		if site != 0 {
			item.Site = siteNames[site]
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportAlertRules(ctx context.Context, tx pgx.Tx, siteNames map[int64]string) ([]exportAlertRule, error) {
	rows, e := tx.Query(ctx, "SELECT r.spec->>'name',(r.spec->>'enabled')::bool,r.spec->>'kind',coalesce((r.spec->>'site_id')::bigint,0),coalesce((r.spec->>'threshold')::int,0),coalesce((r.spec->>'window_minutes')::int,0),coalesce((r.spec->>'cooldown_minutes')::int,0),coalesce(array_agg(c.name ORDER BY c.name) FILTER(WHERE c.id IS NOT NULL),'{}') FROM alert_rules r LEFT JOIN notification_channels c ON c.id=ANY(r.channel_ids) GROUP BY r.id,r.spec ORDER BY r.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []exportAlertRule{}
	for rows.Next() {
		var item exportAlertRule
		var site int64
		if e = rows.Scan(&item.Name, &item.Enabled, &item.Kind, &site, &item.Threshold, &item.WindowMinutes, &item.CooldownMinutes, &item.Channels); e != nil {
			return nil, e
		}
		if site != 0 {
			item.Site = siteNames[site]
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportSettingsSection(ctx context.Context, tx pgx.Tx) (*exportSettings, error) {
	out := &exportSettings{}
	retention, audit := 0, 0
	if e := tx.QueryRow(ctx, "SELECT retention_hours,audit_retention_hours FROM log_settings WHERE id").Scan(&retention, &audit); e != nil {
		return nil, e
	}
	out.LogRetentionHours = &retention
	out.AuditRetentionHours = &audit
	var raw []byte
	if e := tx.QueryRow(ctx, "SELECT settings FROM rate_state WHERE id").Scan(&raw); e != nil {
		return nil, e
	}
	if len(raw) > 0 {
		out.RateState = append(json.RawMessage{}, raw...)
	}
	var exists bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ai_provider WHERE id)").Scan(&exists); e != nil {
		return nil, e
	}
	if exists {
		provider := exportAIProvider{}
		var models []byte
		if e := tx.QueryRow(ctx, "SELECT base_url,model,models FROM ai_provider WHERE id").Scan(&provider.BaseURL, &provider.Model, &models); e != nil {
			return nil, e
		}
		if len(models) > 0 {
			if e := json.Unmarshal(models, &provider.Models); e != nil {
				return nil, e
			}
		}
		out.AIProvider = &provider
	}
	agentEnabled := false
	if e := tx.QueryRow(ctx, "SELECT enabled FROM agent_access WHERE id").Scan(&agentEnabled); e != nil {
		return nil, e
	}
	out.AgentAccessEnabled = &agentEnabled
	if e := tx.QueryRow(ctx, "SELECT public_ip FROM local_location WHERE id").Scan(&out.LocalPublicIP); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, "SELECT kind,enabled,auto_sync FROM geo_sources ORDER BY kind")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out.GeoSources = []exportGeoSource{}
	for rows.Next() {
		var item exportGeoSource
		if e = rows.Scan(&item.Kind, &item.Enabled, &item.AutoSync); e != nil {
			return nil, e
		}
		out.GeoSources = append(out.GeoSources, item)
	}
	return out, rows.Err()
}

func (a *App) exportConfig(w http.ResponseWriter, r *http.Request, _ identity) error {
	bundle, e := a.buildConfigBundle(r.Context())
	if e != nil {
		return e
	}
	w.Header().Set("Content-Disposition", "attachment; filename=aegis-config-bundle.json")
	respond(w, 200, bundle)
	return nil
}

type configImportInput struct {
	Bundle configBundle `json:"bundle"`
	DryRun bool         `json:"dry_run"`
}

func (a *App) importConfig(w http.ResponseWriter, r *http.Request, i identity) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return apiError{415, "Content-Type must be application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, configImportBodyLimit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	var input configImportInput
	if e := d.Decode(&input); e != nil {
		return invalid("invalid JSON request")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return invalid("provide one JSON object")
	}
	if input.Bundle.BundleVersion != configBundleVersion {
		return invalid(fmt.Sprintf("unsupported bundle version %d; this deployment imports bundle version %d (export again from a matching release)", input.Bundle.BundleVersion, configBundleVersion))
	}
	if input.Bundle.Secrets != configBundleSecrets {
		return invalid("bundle does not declare the expected secrets policy")
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT version FROM config_version WHERE id FOR UPDATE"); e != nil {
		return e
	}
	var schema int
	if e = tx.QueryRow(r.Context(), "SELECT max(version) FROM schema_version").Scan(&schema); e != nil {
		return e
	}
	if input.Bundle.SchemaVersion > schema {
		return invalid(fmt.Sprintf("bundle was exported from database schema version %d but this deployment runs schema version %d; upgrade this deployment before importing", input.Bundle.SchemaVersion, schema))
	}
	report, e := a.applyBundle(r.Context(), tx, &input.Bundle, i.Username)
	if e != nil {
		return e
	}
	report.DryRun = input.DryRun
	if input.DryRun {
		// The deferred rollback discards every write above; the report is
		// still the exact plan an apply would run.
		respond(w, 200, report)
		return nil
	}
	if _, e = tx.Exec(r.Context(), "UPDATE config_version SET version=version+1 WHERE id"); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "config.imported", strconv.Itoa(len(report.Changes))); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, report)
	return nil
}

// applyBundle validates and writes the bundle inside the caller's
// transaction. Sections run in dependency order and every write goes through
// the same validators the dashboard API uses, so a malformed bundle fails with
// the API's own errors instead of reaching the load path.
func (a *App) applyBundle(ctx context.Context, tx pgx.Tx, bundle *configBundle, actor string) (*importReport, error) {
	report := &importReport{Changes: []importChange{}, Summary: map[string][3]int{}}
	objects, groups, e := importAddresses(ctx, tx, bundle, report)
	if e != nil {
		return nil, e
	}
	certs, e := importCertificates(ctx, tx, bundle, report)
	if e != nil {
		return nil, e
	}
	if e = importSignatureSets(ctx, tx, bundle, report); e != nil {
		return nil, e
	}
	sites, e := importSites(ctx, tx, bundle, report, certs, objects, groups)
	if e != nil {
		return nil, e
	}
	rules, e := importRules(ctx, tx, bundle, report, sites)
	if e != nil {
		return nil, e
	}
	if e = importPolicies(ctx, tx, bundle, report, sites, rules, objects, groups, actor); e != nil {
		return nil, e
	}
	if e = importRuleFeeds(ctx, tx, bundle, report, sites); e != nil {
		return nil, e
	}
	if e = importAlertRules(ctx, tx, bundle, report, sites); e != nil {
		return nil, e
	}
	if e = importSettings(ctx, tx, bundle, report); e != nil {
		return nil, e
	}
	if e = checkPolicyAssignments(ctx, tx, a.managedEngineLimit()); e != nil {
		return nil, e
	}
	if e = validateAddressConsumers(ctx, tx); e != nil {
		return nil, e
	}
	return report, nil
}

func importAddresses(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport) (map[int64]int64, map[int64]int64, error) {
	objects := map[int64]int64{}
	names := map[string]int64{}
	for _, item := range bundle.AddressObjects {
		value, e := normalizeAddressValue(item.Value)
		if e != nil {
			return nil, nil, e
		}
		name := strings.TrimSpace(item.Name)
		if len(name) < 1 || len(name) > 120 || len(item.Description) > 2000 {
			return nil, nil, invalid("provide an address object name of 1–120 bytes and description up to 2000 bytes")
		}
		var id int64
		var currentValue string
		var currentLocal bool
		e = tx.QueryRow(ctx, "SELECT id,value,is_local FROM address_objects WHERE lower(name)=lower($1)", name).Scan(&id, &currentValue, &currentLocal)
		switch {
		case e == nil:
			objects[item.ID] = id
			names[name] = id
			if currentValue == value && currentLocal == item.IsLocal {
				report.record("address_objects", "skip", name, "")
				continue
			}
			if _, e = tx.Exec(ctx, "UPDATE address_objects SET value=$2,is_local=$3,description=$4,updated_at=now() WHERE id=$1", id, value, item.IsLocal, item.Description); e != nil {
				return nil, nil, e
			}
			report.record("address_objects", "update", name, "")
		case errors.Is(e, pgx.ErrNoRows):
			if e = tx.QueryRow(ctx, "INSERT INTO address_objects(name,description,value,is_local) VALUES($1,$2,$3,$4) RETURNING id", name, item.Description, value, item.IsLocal).Scan(&id); e != nil {
				return nil, nil, e
			}
			objects[item.ID] = id
			names[name] = id
			report.record("address_objects", "create", name, "")
		default:
			return nil, nil, e
		}
	}
	groups := map[int64]int64{}
	for _, item := range bundle.AddressGroups {
		name := strings.TrimSpace(item.Name)
		if len(name) < 1 || len(name) > 120 || len(item.Description) > 2000 {
			return nil, nil, invalid("provide an address group name of 1–120 bytes and description up to 2000 bytes")
		}
		if len(item.Objects) < 1 || len(item.Objects) > 128 {
			return nil, nil, invalid("groups require 1–128 objects")
		}
		ids := []int64{}
		seen := map[string]bool{}
		for _, object := range item.Objects {
			id, ok := names[object]
			if !ok {
				return nil, nil, invalid("address group references object '" + object + "' that the bundle does not contain")
			}
			if seen[object] {
				return nil, nil, invalid("select each valid address object once")
			}
			seen[object] = true
			ids = append(ids, id)
		}
		var groupID int64
		e := tx.QueryRow(ctx, "SELECT id FROM address_groups WHERE lower(name)=lower($1)", name).Scan(&groupID)
		switch {
		case e == nil:
			groups[item.ID] = groupID
			if _, e = tx.Exec(ctx, "UPDATE address_groups SET description=$2,object_ids=$3,updated_at=now() WHERE id=$1", groupID, item.Description, ids); e != nil {
				return nil, nil, e
			}
			report.record("address_groups", "update", name, "")
		case errors.Is(e, pgx.ErrNoRows):
			if e = tx.QueryRow(ctx, "INSERT INTO address_groups(name,description,object_ids) VALUES($1,$2,$3) RETURNING id", name, item.Description, ids).Scan(&groupID); e != nil {
				return nil, nil, e
			}
			groups[item.ID] = groupID
			report.record("address_groups", "create", name, "")
		default:
			return nil, nil, e
		}
	}
	return objects, groups, nil
}

func importCertificates(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport) (map[string]int64, error) {
	certs := map[string]int64{}
	for _, item := range bundle.Certificates {
		name := strings.TrimSpace(item.Name)
		if len(name) < 1 || len(name) > 120 {
			return nil, invalid("certificate names must be 1–120 bytes")
		}
		if item.Origin != "upload" && item.Origin != "acme" {
			return nil, invalid("certificate origin must be upload or acme")
		}
		if item.ChallengeType != "http-01" && item.ChallengeType != "dns-01" {
			return nil, invalid("certificate challenge type must be http-01 or dns-01")
		}
		if item.RenewBeforeDays != nil && (*item.RenewBeforeDays < 1 || *item.RenewBeforeDays > 365) {
			return nil, invalid("certificate renewal window must be 1–365 days")
		}
		if _, e := domains(item.Domains); e != nil {
			return nil, invalid(e.Error())
		}
		leaf, leafErr := pemLeaf(item.ChainPEM)
		if leafErr != nil || leaf == nil {
			return nil, invalid("certificate '" + name + "' has no parseable public chain")
		}
		var id int64
		var chain string
		e := tx.QueryRow(ctx, "SELECT id,chain_pem FROM certificates WHERE name=$1", name).Scan(&id, &chain)
		switch {
		case e == nil:
			certs[name] = id
			if chain == item.ChainPEM {
				report.record("certificates", "skip", name, "public material only; private keys are never exported")
			} else {
				// Never clobber a certificate the deployment already holds:
				// its row may carry a sealed private key that matches the
				// local chain, and overwriting the chain would break TLS.
				report.record("certificates", "skip", name, "kept this deployment's certificate; the bundle's public chain differs")
			}
		case errors.Is(e, pgx.ErrNoRows):
			if e = tx.QueryRow(ctx, "INSERT INTO certificates(name,origin,domains,chain_pem,issuer,not_before,not_after,challenge_type,renew_before_days) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id", name, item.Origin, item.Domains, item.ChainPEM, item.Issuer, item.NotBefore, item.NotAfter, item.ChallengeType, item.RenewBeforeDays).Scan(&id); e != nil {
				return nil, e
			}
			certs[name] = id
			report.record("certificates", "create", name, "public chain only; re-upload the private key or renew via ACME to serve TLS")
		default:
			return nil, e
		}
	}
	return certs, nil
}

func importSignatureSets(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport) error {
	for _, item := range bundle.SignatureSets {
		var digest string
		e := tx.QueryRow(ctx, "SELECT digest FROM signature_sets WHERE id=$1", item.ID).Scan(&digest)
		if errors.Is(e, pgx.ErrNoRows) {
			return invalid("managed signature set '" + item.ID + "' (" + item.Name + " " + item.Version + ") is not loaded on this deployment; install it before importing this bundle")
		}
		if e != nil {
			return e
		}
		if digest != item.Digest {
			return invalid("managed signature set '" + item.ID + "' has digest " + digest + " but the bundle expects " + item.Digest + "; install the matching set version before importing")
		}
		report.record("signature_sets", "skip", item.ID, "reference verified against the loaded set")
	}
	return nil
}

func importSites(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport, certs map[string]int64, objects, groups map[int64]int64) (map[string]int64, error) {
	sites := map[string]int64{}
	for _, item := range bundle.Sites {
		if len(strings.TrimSpace(item.Name)) == 0 || len(item.Name) > 120 {
			return nil, invalid("site name must be 1–120 characters")
		}
		site := Site{
			Name: strings.TrimSpace(item.Name), Hostnames: item.Hostnames, Upstream: item.Upstream,
			RedirectHTTPS: item.RedirectHTTPS, PreserveHost: item.PreserveHost, Enabled: item.Enabled,
			TrafficProfile: item.TrafficProfile, StreamWindowBytes: item.StreamWindow,
			BlockTitle: item.BlockTitle, BlockContact: item.BlockContact, BlockReference: item.BlockReference,
		}
		if present(item.UpstreamTLS) {
			settings, e := decodeUpstreamTLS(item.UpstreamTLS)
			if e != nil {
				return nil, invalid("site '" + site.Name + "': invalid upstream TLS settings")
			}
			site.UpstreamTLS = settings
		}
		if item.Certificate != "" {
			id, ok := certs[item.Certificate]
			if !ok {
				return nil, invalid("site '" + site.Name + "' references certificate '" + item.Certificate + "' that the bundle does not contain")
			}
			site.CertificateID = &id
		}
		if present(item.Protection) {
			var protection ProtectionSettings
			if e := json.Unmarshal(item.Protection, &protection); e != nil {
				return nil, invalid("site '" + site.Name + "': invalid protection settings")
			}
			for _, selection := range []*addressSelection{&protection.TrustedAddresses, &protection.FloodExemptAddresses, &protection.BotExemptAddresses} {
				if e := remapSelectionIDs(selection, objects, groups); e != nil {
					return nil, e
				}
			}
			site.Protection = &protection
		}
		if present(item.Headers) {
			var headers HeaderSettings
			if e := json.Unmarshal(item.Headers, &headers); e != nil {
				return nil, invalid("site '" + site.Name + "': invalid header settings")
			}
			site.Headers = &headers
		}
		// The checks below mirror saveSite: the same normalizers and
		// validations the dashboard applies run here so an import can never
		// be looser than the API.
		if e := normalizeSiteTraffic(&site); e != nil {
			return nil, e
		}
		if site.Headers != nil {
			normalized, e := normalizeHeaders(*site.Headers)
			if e != nil {
				return nil, e
			}
			site.Headers = &normalized
		}
		if site.Protection != nil {
			compiled, e := compileProtection(*site.Protection)
			if e != nil {
				return nil, e
			}
			site.Protection = &compiled.ProtectionSettings
		}
		hostnames, e := domains(site.Hostnames)
		if e != nil {
			return nil, invalid(e.Error())
		}
		site.Hostnames = hostnames
		if e = validateUpstream(site.Upstream); e != nil {
			return nil, invalid(e.Error())
		}
		if site.RedirectHTTPS && site.CertificateID == nil {
			return nil, invalid("attach a valid certificate before enabling HTTPS redirect")
		}
		if site.CertificateID != nil {
			var chain string
			if e = tx.QueryRow(ctx, "SELECT chain_pem FROM certificates WHERE id=$1", *site.CertificateID).Scan(&chain); e != nil {
				return nil, e
			}
			leaf, _ := pemLeaf(chain)
			if leaf == nil {
				return nil, invalid("certificate '" + item.Certificate + "' has no parseable public chain")
			}
			if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
				return nil, invalid("certificate '" + item.Certificate + "' is not currently valid; renew on the source deployment and export again before importing")
			}
			if e = covers(leaf, site.Hostnames); e != nil {
				return nil, invalid(e.Error())
			}
		}
		var id int64
		e = tx.QueryRow(ctx, "SELECT id FROM sites WHERE name=$1", site.Name).Scan(&id)
		switch {
		case e == nil:
			if _, e = tx.Exec(ctx, "UPDATE sites SET name=$2,hostnames=$3,upstream=$4,certificate_id=$5,redirect_https=$6,preserve_host=$7,enabled=$8,traffic_profile=$9,stream_window_bytes=$10,upstream_tls=$11,block_title=$12,block_contact=$13,block_reference=$14 WHERE id=$1", id, site.Name, site.Hostnames, site.Upstream, site.CertificateID, site.RedirectHTTPS, site.PreserveHost, site.Enabled, site.TrafficProfile, site.StreamWindowBytes, marshalUpstreamTLS(site.UpstreamTLS), site.BlockTitle, site.BlockContact, site.BlockReference); e != nil {
				return nil, e
			}
			report.record("sites", "update", site.Name, "")
		case errors.Is(e, pgx.ErrNoRows):
			if e = tx.QueryRow(ctx, "INSERT INTO sites(name,hostnames,upstream,certificate_id,redirect_https,preserve_host,enabled,traffic_profile,stream_window_bytes,upstream_tls,block_title,block_contact,block_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id", site.Name, site.Hostnames, site.Upstream, site.CertificateID, site.RedirectHTTPS, site.PreserveHost, site.Enabled, site.TrafficProfile, site.StreamWindowBytes, marshalUpstreamTLS(site.UpstreamTLS), site.BlockTitle, site.BlockContact, site.BlockReference).Scan(&id); e != nil {
				return nil, e
			}
			report.record("sites", "create", site.Name, "")
		default:
			return nil, e
		}
		sites[site.Name] = id
		for _, hostname := range site.Hostnames {
			var exists bool
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM site_hosts WHERE hostname=$1 AND site_id<>$2)", hostname, id).Scan(&exists); e != nil {
				return nil, e
			}
			if exists {
				return nil, apiError{409, "hostname is already assigned to another site"}
			}
		}
		if _, e = tx.Exec(ctx, "DELETE FROM site_hosts WHERE site_id=$1", id); e != nil {
			return nil, e
		}
		for _, hostname := range site.Hostnames {
			if _, e = tx.Exec(ctx, "INSERT INTO site_hosts(hostname,site_id) VALUES($1,$2)", hostname, id); e != nil {
				return nil, e
			}
		}
		if present(item.Protection) {
			raw, _ := json.Marshal(site.Protection)
			if _, e = tx.Exec(ctx, "INSERT INTO protection_settings(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", id, raw); e != nil {
				return nil, e
			}
		}
		if present(item.Headers) {
			raw, _ := json.Marshal(site.Headers)
			if e = storeHeaderSettings(ctx, tx, id, raw); e != nil {
				return nil, e
			}
		}
		if present(item.Traffic) {
			var settings TrafficSettings
			if e = json.Unmarshal(item.Traffic, &settings); e != nil {
				return nil, invalid("site '" + site.Name + "': invalid traffic settings")
			}
			if e = validateTrafficSettings(settings); e != nil {
				return nil, invalid(e.Error())
			}
			if _, e = tx.Exec(ctx, "INSERT INTO traffic_settings(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", id, item.Traffic); e != nil {
				return nil, e
			}
		}
	}
	return sites, nil
}

func importRules(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport, sites map[string]int64) (map[int64]int64, error) {
	rules := map[int64]int64{}
	for index := range bundle.Rules {
		item := &bundle.Rules[index]
		site, ok := sites[item.Site]
		if !ok {
			return nil, invalid("rule references application '" + item.Site + "' that the bundle does not contain")
		}
		var spec RuleSpec
		if e := json.Unmarshal(item.Spec, &spec); e != nil {
			return nil, invalid("rule for '" + item.Site + "': invalid rule spec")
		}
		if len(spec.EvidenceIDs) > 0 {
			report.warn("rule '" + spec.Name + "': evidence references are runtime state and were not imported")
			spec.EvidenceIDs = nil
		}
		spec.Scope.SiteID = site
		if _, e := compileRule(spec); e != nil {
			return nil, invalid(e.Error())
		}
		data, _ := json.Marshal(spec)
		canonical := func(raw []byte) string {
			var other RuleSpec
			if json.Unmarshal(raw, &other) != nil {
				return string(raw)
			}
			other.Scope.SiteID = 0
			other.EvidenceIDs = nil
			out, _ := json.Marshal(other)
			return string(out)
		}
		current, e := tx.Query(ctx, "SELECT id,spec,enabled,expires_at FROM rules WHERE site_id=$1", site)
		if e != nil {
			return nil, e
		}
		matchID, matchAction := int64(0), ""
		for current.Next() {
			var rowID int64
			var raw []byte
			var enabled bool
			var expires *time.Time
			if e = current.Scan(&rowID, &raw, &enabled, &expires); e != nil {
				current.Close()
				return nil, e
			}
			if canonical(raw) != canonical(data) {
				continue
			}
			matchID = rowID
			if enabled == item.Enabled && sameExpiry(expires, item.ExpiresAt) {
				matchAction = "skip"
			} else {
				matchAction = "update"
			}
			break
		}
		current.Close()
		if e = current.Err(); e != nil {
			return nil, e
		}
		if matchID != 0 {
			rules[item.ID] = matchID
			if matchAction == "skip" {
				report.record("rules", "skip", spec.Name, "")
				continue
			}
			if _, e = tx.Exec(ctx, "UPDATE rules SET spec=$2,enabled=$3,expires_at=$4,revision=revision+1,updated_at=now() WHERE id=$1", matchID, data, item.Enabled, item.ExpiresAt); e != nil {
				return nil, e
			}
			report.record("rules", "update", spec.Name, "")
			continue
		}
		if e = checkRuleSite(ctx, tx, site, 0); e != nil {
			return nil, e
		}
		var newID int64
		if e = tx.QueryRow(ctx, "INSERT INTO rules(site_id,spec,enabled,expires_at) VALUES($1,$2,$3,$4) RETURNING id", site, data, item.Enabled, item.ExpiresAt).Scan(&newID); e != nil {
			return nil, e
		}
		rules[item.ID] = newID
		report.record("rules", "create", spec.Name, "")
	}
	return rules, nil
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// remapSelectionIDs rewrites exported address references to the IDs this
// import created. Unresolvable references fail the import: policy and
// protection settings must never point at objects the target lacks.
func remapSelectionIDs(selection *addressSelection, objects, groups map[int64]int64) error {
	for index, id := range selection.ObjectIDs {
		mapped, ok := objects[id]
		if !ok {
			return invalid("settings reference an address object that the bundle does not contain")
		}
		selection.ObjectIDs[index] = mapped
	}
	for index, id := range selection.GroupIDs {
		mapped, ok := groups[id]
		if !ok {
			return invalid("settings reference an address group that the bundle does not contain")
		}
		selection.GroupIDs[index] = mapped
	}
	return nil
}

// remapPolicySpec rewrites exported rule and address references inside a
// policy spec to the IDs this import created. Feed-derived rules keep their
// embedded snapshots and catalogue provenance; their IDs re-link on the next
// feed sync. Historical revisions whose references no longer resolve are
// skipped by the caller with a warning; the current spec must resolve fully.
func remapPolicySpec(raw []byte, rules, objects, groups map[int64]int64) (json.RawMessage, bool, error) {
	var spec policySpec
	if e := json.Unmarshal(raw, &spec); e != nil {
		return nil, false, invalid("policy spec is not valid")
	}
	for g := range spec.Groups {
		for index := range spec.Groups[g].Rules {
			rule := &spec.Groups[g].Rules[index]
			if rule.Feed != nil {
				continue
			}
			mapped, ok := rules[rule.RuleID]
			if !ok {
				return nil, false, invalid("policy group references rule " + strconv.FormatInt(rule.RuleID, 10) + " which the bundle does not contain")
			}
			rule.RuleID = mapped
		}
	}
	for _, selection := range []*addressSelection{&spec.NetworkAccess.BlockAddresses, &spec.NetworkAccess.AllowAddresses} {
		if e := remapSelectionIDs(selection, objects, groups); e != nil {
			return nil, false, e
		}
	}
	out, e := json.Marshal(spec)
	if e != nil {
		return nil, false, e
	}
	return out, true, nil
}

func importPolicies(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport, sites map[string]int64, rules, objects, groups map[int64]int64, actor string) error {
	for _, item := range bundle.Policies {
		raw, _, e := remapPolicySpec(item.Spec, rules, objects, groups)
		if e != nil {
			return e
		}
		var spec policySpec
		if e = json.Unmarshal(raw, &spec); e != nil {
			return e
		}
		// The validation below mirrors the load path and savePolicy: an
		// imported spec must satisfy every check a dashboard-saved policy
		// satisfies, or the import is rejected whole.
		if e = validatePolicySpec(spec); e != nil {
			return e
		}
		managed, e := normalizeManagedSignatures(spec.ManagedSignatures)
		if e != nil {
			return e
		}
		if managed.Mode != "off" {
			if _, e = readSignatureSet(ctx, tx, managed.SetID); e != nil {
				return e
			}
		}
		network, e := compileNetworkAccess(spec.NetworkAccess, spec.Mode)
		if e != nil {
			return e
		}
		if network.Settings.GeoMode != "off" {
			var available bool
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM geo_database WHERE id)").Scan(&available); e != nil {
				return e
			}
			if !available {
				return invalid("download a country database before enabling Geo blocking")
			}
		}
		if _, e = policyProtection(nil, spec, 0); e != nil {
			return e
		}
		// Locate the target policy: built-in keys take precedence (the
		// baseline policy updates in place), then the spec name.
		var id int64
		if item.BuiltIn != "" {
			e = tx.QueryRow(ctx, "SELECT policy_id FROM built_in_policies WHERE key=$1", item.BuiltIn).Scan(&id)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		}
		action := "create"
		if id == 0 {
			if e = tx.QueryRow(ctx, "SELECT id FROM policies WHERE spec->>'name'=$1 ORDER BY id LIMIT 1", spec.Name).Scan(&id); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if id != 0 {
				action = "update"
			}
		} else {
			action = "update"
		}
		if action == "create" {
			var count int
			if e = tx.QueryRow(ctx, "SELECT count(*) FROM policies p WHERE NOT EXISTS(SELECT 1 FROM built_in_policies b WHERE b.policy_id=p.id)").Scan(&count); e != nil {
				return e
			}
			if count >= 50 {
				return apiError{409, "at most 50 custom policies are supported"}
			}
			if e = tx.QueryRow(ctx, "INSERT INTO policies(spec,revision) VALUES($1,$2) RETURNING id", raw, item.Revision).Scan(&id); e != nil {
				return e
			}
			if item.BuiltIn != "" {
				if _, e = tx.Exec(ctx, "INSERT INTO built_in_policies(key,policy_id) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", item.BuiltIn, id); e != nil {
					return e
				}
			}
		} else {
			var revision int64
			if e = tx.QueryRow(ctx, "SELECT revision FROM policies WHERE id=$1 FOR UPDATE", id).Scan(&revision); e != nil {
				return e
			}
			next := item.Revision
			if revision > next {
				next = revision
			}
			if _, e = tx.Exec(ctx, "UPDATE policies SET spec=$2,revision=$3 WHERE id=$1", id, raw, next); e != nil {
				return e
			}
		}
		report.record("policies", action, spec.Name, "")
		// Assignments follow savePolicy's semantics, including displacing a
		// previous default assignment on the same site.
		if _, e = tx.Exec(ctx, "DELETE FROM policy_assignments WHERE policy_id=$1", id); e != nil {
			return e
		}
		for _, assignment := range item.Assignments {
			site, ok := sites[assignment.Site]
			if !ok {
				return invalid("policy assignment references application '" + assignment.Site + "' that the bundle does not contain")
			}
			if len(assignment.SourceCIDRs) == 0 {
				displaced, e := tx.Query(ctx, "DELETE FROM policy_assignments WHERE site_id=$1 AND cardinality(source_cidrs)=0 AND policy_id<>$2 RETURNING policy_id", site, id)
				if e != nil {
					return e
				}
				previous := []int64{}
				for displaced.Next() {
					var pid int64
					if e = displaced.Scan(&pid); e != nil {
						displaced.Close()
						return e
					}
					previous = append(previous, pid)
				}
				displaced.Close()
				if e = displaced.Err(); e != nil {
					return e
				}
				// Writes happen only after the result set is drained: pgx
				// streams rows, so an Exec during iteration would fail.
				for _, pid := range previous {
					if _, e = tx.Exec(ctx, "UPDATE policies SET revision=revision+1 WHERE id=$1", pid); e != nil {
						return e
					}
					if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) SELECT id,revision,spec,$2 FROM policies WHERE id=$1", pid, actor); e != nil {
						return e
					}
				}
				if _, e = tx.Exec(ctx, "INSERT INTO policy_assignments(policy_id,site_id,source_cidrs,priority) VALUES($1,$2,'{}',10000)", id, site); e != nil {
					return e
				}
				continue
			}
			var conflict bool
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM policy_assignments WHERE site_id=$1 AND priority=$2 AND policy_id<>$3)", site, assignment.Priority, id).Scan(&conflict); e != nil {
				return e
			}
			if conflict {
				return apiError{409, "another CIDR policy has this priority on an application; choose a unique priority"}
			}
			if _, e = tx.Exec(ctx, "INSERT INTO policy_assignments(policy_id,site_id,source_cidrs,priority) VALUES($1,$2,$3,$4)", id, site, assignment.SourceCIDRs, assignment.Priority); e != nil {
				return e
			}
		}
		// Revision history: remap each stored revision; revisions whose
		// references no longer resolve are skipped with a warning so a
		// restore never ships a rollback target that cannot load.
		for _, revision := range item.Revisions {
			historyRaw, ok, e := remapPolicySpec(revision.Spec, rules, objects, groups)
			if e != nil {
				return e
			}
			if !ok {
				report.warn("policy '" + spec.Name + "': revision " + strconv.FormatInt(revision.Revision, 10) + " references removed configuration and was not imported")
				continue
			}
			if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor,at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(policy_id,revision) DO UPDATE SET spec=excluded.spec,actor=excluded.actor,at=excluded.at", id, revision.Revision, historyRaw, revision.Actor, revision.At); e != nil {
				return e
			}
		}
	}
	return nil
}

func importRuleFeeds(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport, sites map[string]int64) error {
	for _, item := range bundle.RuleFeeds {
		name := strings.TrimSpace(item.Name)
		if len(name) < 1 || len(name) > 120 {
			return invalid("provide a feed name of 1–120 bytes")
		}
		if _, e := feedURL(item.URL); e != nil {
			return e
		}
		var site int64
		if item.Site != "" {
			id, ok := sites[item.Site]
			if !ok {
				return invalid("rule feed references application '" + item.Site + "' that the bundle does not contain")
			}
			site = id
		}
		var total int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM rule_feeds").Scan(&total); e != nil {
			return e
		}
		if total >= 20 {
			return apiError{409, "at most 20 rule feeds are supported"}
		}
		var id int64
		e := tx.QueryRow(ctx, "SELECT id FROM rule_feeds WHERE url=$1 AND coalesce(site_id,0)=$2", item.URL, site).Scan(&id)
		switch {
		case e == nil:
			report.record("rule_feeds", "skip", name, "catalogue content re-syncs from the source URL")
		case errors.Is(e, pgx.ErrNoRows):
			if site == 0 {
				var exists bool
				if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rule_feeds WHERE site_id IS NULL AND url=$1)", item.URL).Scan(&exists); e != nil {
					return e
				}
				if exists {
					return apiError{409, "this workspace source is already configured"}
				}
			}
			if e = tx.QueryRow(ctx, "INSERT INTO rule_feeds(name,url,site_id) VALUES($1,$2,nullif($3::bigint,0)) RETURNING id", name, item.URL, site).Scan(&id); e != nil {
				return e
			}
			if site == 0 && item.URL == communityFeedURL {
				if _, e = tx.Exec(ctx, "INSERT INTO built_in_rule_feeds(key,feed_id) VALUES('aegis-community',$1) ON CONFLICT(key) DO UPDATE SET feed_id=excluded.feed_id WHERE built_in_rule_feeds.feed_id IS NULL", id); e != nil {
					return e
				}
			}
			report.record("rule_feeds", "create", name, "catalogue content syncs from the source URL on schedule")
		default:
			return e
		}
		// A bundle carrying a built-in feed key links it when the target has
		// not already claimed that key with another feed.
		if item.BuiltIn != "" && item.BuiltIn != "aegis-community" {
			if _, e = tx.Exec(ctx, "INSERT INTO built_in_rule_feeds(key,feed_id) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET feed_id=excluded.feed_id WHERE built_in_rule_feeds.feed_id IS NULL", item.BuiltIn, id); e != nil {
				return e
			}
		}
	}
	return nil
}

func importAlertRules(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport, sites map[string]int64) error {
	for _, item := range bundle.AlertRules {
		rule := alertRule{
			Name: item.Name, Enabled: item.Enabled, Kind: item.Kind,
			Threshold: item.Threshold, WindowMinutes: item.WindowMinutes, CooldownMinutes: item.CooldownMinutes,
		}
		if item.Site != "" {
			site, ok := sites[item.Site]
			if !ok {
				return invalid("alert rule references application '" + item.Site + "' that the bundle does not contain")
			}
			rule.SiteID = site
		}
		channelIDs := []int64{}
		for _, channel := range item.Channels {
			var id int64
			e := tx.QueryRow(ctx, "SELECT id FROM notification_channels WHERE name=$1", channel).Scan(&id)
			if errors.Is(e, pgx.ErrNoRows) {
				report.warn("alert rule '" + item.Name + "': destination '" + channel + "' has no matching channel here (channel payloads are never exported); re-link it after creating the channel")
				continue
			}
			if e != nil {
				return e
			}
			channelIDs = append(channelIDs, id)
		}
		rule.ChannelIDs = channelIDs
		if e := normalizeAlertRule(&rule); e != nil {
			return e
		}
		raw, _ := json.Marshal(rule)
		var id int64
		e := tx.QueryRow(ctx, "SELECT id FROM alert_rules WHERE spec->>'name'=$1 AND coalesce((spec->>'site_id')::bigint,0)=coalesce($2::bigint,0)", item.Name, rule.SiteID).Scan(&id)
		switch {
		case e == nil:
			if _, e = tx.Exec(ctx, "UPDATE alert_rules SET spec=$2,channel_ids=$3,revision=revision+1,created_at=now(),last_emitted=NULL,next_eval=now() WHERE id=$1", id, raw, channelIDs); e != nil {
				return e
			}
			report.record("alert_rules", "update", item.Name, "")
		case errors.Is(e, pgx.ErrNoRows):
			var count int
			if e = tx.QueryRow(ctx, "SELECT count(*) FROM alert_rules").Scan(&count); e != nil {
				return e
			}
			if count >= 64 {
				return invalid("alert rule limit reached (64)")
			}
			if e = tx.QueryRow(ctx, "INSERT INTO alert_rules(spec,channel_ids) VALUES($1,$2) RETURNING id", raw, channelIDs).Scan(&id); e != nil {
				return e
			}
			report.record("alert_rules", "create", item.Name, "")
		default:
			return e
		}
	}
	return nil
}

func importSettings(ctx context.Context, tx pgx.Tx, bundle *configBundle, report *importReport) error {
	settings := bundle.Settings
	if settings == nil {
		return nil
	}
	if settings.LogRetentionHours != nil {
		retention := *settings.LogRetentionHours
		auditHours := 0
		if settings.AuditRetentionHours != nil {
			auditHours = *settings.AuditRetentionHours
		}
		if retention < 1 || retention > 8760 {
			return invalid("retention_hours must be 1–8760")
		}
		if auditHours < 0 || auditHours > 8760 {
			return invalid("audit_retention_hours must be 0–8760")
		}
		if auditHours == 0 {
			if e := tx.QueryRow(ctx, "SELECT audit_retention_hours FROM log_settings WHERE id FOR SHARE").Scan(&auditHours); e != nil {
				return e
			}
		}
		if _, e := tx.Exec(ctx, "UPDATE log_settings SET retention_hours=$1,audit_retention_hours=$2,revision=revision+1 WHERE id", retention, auditHours); e != nil {
			return e
		}
		report.record("settings", "update", "log_settings", "")
	}
	if present(settings.RateState) {
		var rate rateStateSettings
		if e := json.Unmarshal(settings.RateState, &rate); e != nil {
			return invalid("rate-state settings are not valid")
		}
		normalized, e := normalizeRateState(rate)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(normalized)
		// Credentials are sealed under this deployment's key and never
		// exported: only the settings shape is restored.
		if _, e = tx.Exec(ctx, "UPDATE rate_state SET settings=$1,revision=revision+1 WHERE id", raw); e != nil {
			return e
		}
		report.record("settings", "update", "rate_state", "backend settings only; credentials stay on this deployment")
	}
	if settings.AIProvider != nil {
		provider := settings.AIProvider
		if provider.BaseURL != "" && !strings.HasPrefix(provider.BaseURL, "https://") && !strings.HasPrefix(provider.BaseURL, "http://") {
			return invalid("AI provider base URL must be http(s)")
		}
		if len(provider.Model) < 1 || len(provider.Model) > 200 {
			return invalid("AI provider model must be 1–200 bytes")
		}
		models, _ := json.Marshal(provider.Models)
		if _, e := tx.Exec(ctx, "UPDATE ai_provider SET base_url=$1,model=$2,models=$3,revision=revision+1 WHERE id", provider.BaseURL, provider.Model, models); e != nil {
			return e
		}
		report.record("settings", "update", "ai_provider", "API key is never exported; re-enter it after restore")
	}
	if settings.AgentAccessEnabled != nil {
		if _, e := tx.Exec(ctx, "UPDATE agent_access SET enabled=$1 WHERE id", *settings.AgentAccessEnabled); e != nil {
			return e
		}
		report.record("settings", "update", "agent_access", "")
	}
	if settings.LocalPublicIP != "" {
		if _, e := netip.ParseAddr(settings.LocalPublicIP); e != nil {
			return invalid("local network public IP must be a valid address")
		}
		if _, e := tx.Exec(ctx, "UPDATE local_location SET public_ip=$1 WHERE id", settings.LocalPublicIP); e != nil {
			return e
		}
		report.record("settings", "update", "local_location", "")
	}
	for _, source := range settings.GeoSources {
		if source.Kind != "country" && source.Kind != "city" {
			return invalid("geo source kind must be country or city")
		}
		var updated int64
		tag, e := tx.Exec(ctx, "UPDATE geo_sources SET enabled=$2,auto_sync=$3 WHERE kind=$1", source.Kind, source.Enabled, source.AutoSync)
		if e != nil {
			return e
		}
		updated = tag.RowsAffected()
		if updated == 0 {
			if _, e := tx.Exec(ctx, "INSERT INTO geo_sources(kind,enabled,auto_sync,status,next_sync) VALUES($1,$2,$3,'queued',now())", source.Kind, source.Enabled, source.AutoSync); e != nil {
				return e
			}
		}
	}
	if len(settings.GeoSources) > 0 {
		report.record("settings", "update", "geo_sources", "")
	}
	return nil
}
