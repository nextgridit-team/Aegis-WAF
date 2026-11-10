package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	community "github.com/nextgridit-team/Aegis-WAF/rules/community"
)

func normalizeCommunityUpdateMode(mode string) (string, error) {
	if mode == "" {
		mode = "pinned"
	}
	if mode != "pinned" && mode != "follow" {
		return "", invalid("community update_mode must be pinned or follow")
	}
	return mode, nil
}

// Only the built-in source at its official URL may automatically publish rules.
// Custom catalogues retain their explicit review and snapshot workflow.
func officialCommunityRules(ctx context.Context, tx pgx.Tx) (int64, []policyRule, error) {
	var feedID int64
	e := tx.QueryRow(ctx, "SELECT f.id FROM rule_feeds f JOIN built_in_rule_feeds b ON b.feed_id=f.id WHERE b.key='aegis-community' AND f.url=$1", communityFeedURL).Scan(&feedID)
	if e == pgx.ErrNoRows {
		return 0, nil, nil
	}
	if e != nil {
		return 0, nil, e
	}
	rows, e := tx.Query(ctx, "SELECT id FROM rule_catalog WHERE feed_id=$1 AND available ORDER BY id LIMIT 2001", feedID)
	if e != nil {
		return 0, nil, e
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return 0, nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, nil, e
	}
	if len(ids) > 2000 {
		return 0, nil, invalid("official feed exceeds catalogue capacity")
	}
	rules := []policyRule{}
	for _, id := range ids {
		rule, e := (&App{}).readPolicyLibraryRule(ctx, tx, id)
		if e != nil {
			return 0, nil, e
		}
		rules = append(rules, rule)
	}
	return feedID, rules, nil
}

func followedCommunityRules(old []policyRule, feedID int64, current []policyRule) []policyRule {
	rules := []policyRule{}
	for _, rule := range old {
		if rule.Feed == nil || rule.Feed.FeedID != feedID {
			rules = append(rules, rule)
		}
	}
	return append(rules, current...)
}

func applyCommunityFeed(s *policySpec, feedID int64, current []policyRule) {
	s.Community.Rules = followedCommunityRules(s.Community.Rules, feedID, current)
	byID := map[int64]policyRule{}
	for _, rule := range current {
		byID[rule.RuleID] = rule
	}
	for i := range s.Groups {
		kept := []policyRule{}
		for _, rule := range s.Groups[i].Rules {
			if rule.Feed != nil && rule.Feed.FeedID == feedID {
				if next, ok := byID[rule.RuleID]; ok {
					kept = append(kept, next)
				}
			} else {
				kept = append(kept, rule)
			}
		}
		s.Groups[i].Rules = kept
	}
}

func publishCommunityPolicy(ctx context.Context, tx pgx.Tx, id int64, spec policySpec, action string) error {
	if e := validatePolicySpec(spec); e != nil {
		return fmt.Errorf("automatic community policy %d: %w", id, e)
	}
	if e := checkAssignedRuleCapacity(ctx, tx, id, &spec); e != nil {
		return fmt.Errorf("automatic community policy %d: %w", id, e)
	}
	raw, e := json.Marshal(spec)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE policies SET spec=$2,revision=revision+1 WHERE id=$1", id, raw); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) SELECT id,revision,spec,'feed-worker' FROM policies WHERE id=$1", id); e != nil {
		return e
	}
	if e = audit(ctx, tx, "feed-worker", action, strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id")
	return e
}

func pinCommunityFollowers(ctx context.Context, tx pgx.Tx, sourceID int64) error {
	rows, e := tx.Query(ctx, "SELECT id,spec FROM policies WHERE spec->'community_mitigations'->>'update_mode'='follow' AND EXISTS(SELECT 1 FROM built_in_rule_feeds WHERE key='aegis-community' AND feed_id=$1) ORDER BY id FOR UPDATE", sourceID)
	if e != nil {
		return e
	}
	type saved struct {
		id   int64
		spec policySpec
	}
	policies := []saved{}
	for rows.Next() {
		var p saved
		var raw []byte
		if e = rows.Scan(&p.id, &raw); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal(raw, &p.spec); e != nil {
			rows.Close()
			return e
		}
		policies = append(policies, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, p := range policies {
		p.spec.Community.UpdateMode = "pinned"
		if e = publishCommunityPolicy(ctx, tx, p.id, p.spec, "policy.feed_follow_stopped"); e != nil {
			return e
		}
	}
	return nil
}

// Called inside the catalogue transaction under the configuration lock. One bad
// policy aborts the entire release, preserving the previous catalogue and every
// published policy. A 304 still reconciles followers after an application upgrade.
func (a *App) followCommunityPolicies(ctx context.Context, tx pgx.Tx, sourceID int64) error {
	var follows bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM policies WHERE spec->'community_mitigations'->>'update_mode'='follow' AND spec->'community_mitigations'->>'enabled'='true')").Scan(&follows); e != nil {
		return e
	}
	if !follows {
		return nil
	}
	feedID, current, e := officialCommunityRules(ctx, tx)
	if e != nil {
		return e
	}
	if feedID == 0 || feedID != sourceID {
		return nil
	}
	rows, e := tx.Query(ctx, "SELECT id,spec FROM policies WHERE spec->'community_mitigations'->>'update_mode'='follow' AND spec->'community_mitigations'->>'enabled'='true' ORDER BY id FOR UPDATE")
	if e != nil {
		return e
	}
	type saved struct {
		id   int64
		spec policySpec
	}
	policies := []saved{}
	for rows.Next() {
		var p saved
		var raw []byte
		if e = rows.Scan(&p.id, &raw); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal(raw, &p.spec); e != nil {
			rows.Close()
			return e
		}
		policies = append(policies, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, p := range policies {
		before, _ := json.Marshal(p.spec)
		applyCommunityFeed(&p.spec, feedID, current)
		after, _ := json.Marshal(p.spec)
		if bytes.Equal(before, after) {
			continue
		}
		if e = publishCommunityPolicy(ctx, tx, p.id, p.spec, "policy.feed_updated"); e != nil {
			return e
		}
	}
	return nil
}

// Adopt only a provably complete official selection. The frozen v2 manifest is
// the last pre-follow full set, so upgrading after a download is also supported.
// Custom selections/scopes, disabled switches and enforcement modes survive.
func upgradeCommunityFollowing(ctx context.Context, tx pgx.Tx) error {
	feedID, current, e := officialCommunityRules(ctx, tx)
	if e != nil {
		return e
	}
	legacyRaw, e := community.Files.ReadFile("manifest.json")
	if e != nil {
		return e
	}
	var legacy ruleManifest
	if e = json.Unmarshal(legacyRaw, &legacy); e != nil {
		return e
	}
	legacyIDs, currentIDs := map[string]bool{}, map[string]bool{}
	for _, entry := range legacy.Rules {
		legacyIDs[entry.ID] = true
	}
	for _, rule := range current {
		currentIDs[rule.Feed.EntryID] = true
	}
	rows, e := tx.Query(ctx, "SELECT id,spec FROM policies WHERE spec->'community_mitigations' IS NOT NULL AND coalesce(spec->'community_mitigations'->>'update_mode','')='' ORDER BY id FOR UPDATE")
	if e != nil {
		return e
	}
	type saved struct {
		id   int64
		spec policySpec
	}
	policies := []saved{}
	for rows.Next() {
		var p saved
		var raw []byte
		if e = rows.Scan(&p.id, &raw); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal(raw, &p.spec); e != nil {
			rows.Close()
			return e
		}
		policies = append(policies, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	queued := false
	for _, p := range policies {
		if p.spec.Community == nil {
			continue
		}
		full := func(want map[string]bool) bool {
			if feedID == 0 || len(want) == 0 || len(want) != len(p.spec.Community.Rules) {
				return false
			}
			seen := map[string]bool{}
			for _, rule := range p.spec.Community.Rules {
				if rule.Feed == nil || rule.Feed.FeedID != feedID || !want[rule.Feed.EntryID] || seen[rule.Feed.EntryID] {
					return false
				}
				seen[rule.Feed.EntryID] = true
			}
			for _, group := range p.spec.Groups {
				for _, rule := range group.Rules {
					if rule.Feed != nil {
						return false
					}
				}
			}
			return true
		}
		p.spec.Community.UpdateMode = "pinned"
		if full(currentIDs) || full(legacyIDs) {
			p.spec.Community.UpdateMode = "follow"
			queued = true
		}
		if e = publishCommunityPolicy(ctx, tx, p.id, p.spec, "policy.feed_follow_migrated"); e != nil {
			return e
		}
	}
	if queued {
		_, e = tx.Exec(ctx, "UPDATE rule_feeds SET next_sync=now() WHERE id=$1", feedID)
	}
	return e
}
