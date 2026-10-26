package app

import (
	"context"
	"github.com/jackc/pgx/v5"
	community "github.com/nextgridit-team/Aegis-WAF/rules/community"
)

type policyCommunity struct {
	Enabled bool         `json:"enabled"`
	Rules   []policyRule `json:"rules"`
}
type policyCommunityInput struct {
	Enabled bool    `json:"enabled"`
	RuleIDs []int64 `json:"rule_ids"`
}

// Stored groups retain snapshots even when disabled. Effective groups gate all
// feed-derived rules, including legacy catalogue selections with path scopes.
func storedPolicyGroups(s policySpec) []policyGroup {
	groups := append([]policyGroup{}, s.Groups...)
	if s.Community != nil {
		groups = append(groups, policyGroup{Name: "Community mitigations", Rules: s.Community.Rules})
	}
	return groups
}
func effectivePolicyGroups(s policySpec) []policyGroup {
	if s.Community == nil {
		return s.Groups
	}
	selected, existing := map[int64]bool{}, map[int64]bool{}
	if s.Community.Enabled {
		for _, r := range s.Community.Rules {
			selected[r.RuleID] = true
		}
	}
	groups := []policyGroup{}
	for _, group := range s.Groups {
		g := group
		g.Rules = []policyRule{}
		for _, r := range group.Rules {
			if r.Feed == nil || selected[r.RuleID] {
				g.Rules = append(g.Rules, r)
			}
			if r.Feed != nil {
				existing[r.RuleID] = true
			}
		}
		groups = append(groups, g)
	}
	extra := policyGroup{Name: "Community mitigations", Rules: []policyRule{}}
	if s.Community.Enabled {
		for _, r := range s.Community.Rules {
			if !existing[r.RuleID] {
				extra.Rules = append(extra.Rules, r)
			}
		}
	}
	return append(groups, extra)
}
func (a *App) normalizeCommunity(ctx context.Context, tx pgx.Tx, input *policyCommunityInput, frozen map[int64]policyRule) (*policyCommunity, error) {
	if input == nil {
		return nil, nil
	}
	if len(input.RuleIDs) > 100 {
		return nil, invalid("at most 100 community mitigations per policy")
	}
	out := &policyCommunity{Enabled: input.Enabled, Rules: []policyRule{}}
	seen := map[int64]bool{}
	for _, id := range input.RuleIDs {
		if id < 1 || seen[id] {
			return nil, invalid("select each community mitigation only once")
		}
		seen[id] = true
		rule, ok := frozen[id]
		if !ok {
			var e error
			rule, e = a.readPolicyLibraryRule(ctx, tx, id)
			if e != nil {
				return nil, e
			}
		}
		if rule.Feed == nil {
			return nil, invalid("community selections must reference catalogue rules")
		}
		out.Rules = append(out.Rules, rule)
	}
	if input.Enabled && len(out.Rules) == 0 {
		return nil, invalid("select at least one community mitigation")
	}
	return out, nil
}
func communitySelection(ctx context.Context, tx pgx.Tx) (*policyCommunity, error) {
	rows, e := tx.Query(ctx, "SELECT id FROM rule_catalog WHERE available AND feed_id=(SELECT feed_id FROM built_in_rule_feeds WHERE key='aegis-community') ORDER BY id LIMIT 101")
	if e != nil {
		return nil, e
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return (&App{}).normalizeCommunity(ctx, tx, &policyCommunityInput{Enabled: len(ids) > 0, RuleIDs: ids}, nil)
}

// Bundle the shipped feed so the baseline is protected before the first network
// sync. Never reset a downloaded catalogue or recreate a deleted subscription.
func seedCommunityCatalogue(ctx context.Context, tx pgx.Tx) error {
	var id *int64
	var revision int
	e := tx.QueryRow(ctx, "SELECT b.feed_id,coalesce(f.manifest_revision,0) FROM built_in_rule_feeds b LEFT JOIN rule_feeds f ON f.id=b.feed_id WHERE b.key='aegis-community'").Scan(&id, &revision)
	if e != nil {
		return e
	}
	if id == nil || revision != 0 {
		return nil
	}
	raw, e := community.Files.ReadFile("release.json")
	if e != nil {
		return e
	}
	base, e := feedURL(communityFeedURL)
	if e != nil {
		return e
	}
	manifest, e := parseRuleManifest(raw, base)
	if e != nil {
		return e
	}
	raw, e = community.Files.ReadFile(manifest.Package.Path)
	if e != nil {
		return e
	}
	candidates, e := parseCataloguePackage(ctx, manifest, raw)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "SELECT version FROM config_version WHERE id FOR UPDATE"); e != nil {
		return e
	}
	return commitCatalogue(ctx, tx, *id, manifest, candidates)
}
