package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Feed growth policy: a compromised or misfiring upstream catalogue must not
// be able to grow a deployment without bound. Two deliberate, configurable
// caps bound the stored rule catalogue:
//
//   - a per-source rule cap (RULE_FEED_SOURCE_LIMIT, default 2000, capped at
//     the package format bound of 2000 rules per release) bounding the rules
//     any single source may grow to, workspace catalogues and application
//     feeds alike, signed or untrusted;
//   - a global community-rule budget (COMMUNITY_RULE_BUDGET, default 2000,
//     maximum 20000) bounding the total rules stored across every workspace
//     catalogue source.
//
// Both are enforced inside the catalogue import transaction: an import that
// would grow a source or the workspace past its cap is refused, the source
// records the error, retries in 12 hours and keeps its last-good catalogue —
// there is never partial application and never silent truncation. Caps bound
// growth, not incumbents: an existing catalogue that already exceeds a lowered
// cap may still take same-size replacement releases and may shrink, but any
// further growth is refused. The bundled community baseline is exempt because
// it ships inside the image (build-bounded, never network-fed); the caps apply
// to every network sync regardless of trust class.
//
// Parse-time memory is bounded independently of these caps by the format
// checks in feed_catalog_format.go and feed_package.go (4 KiB schema-3
// descriptor, 1 MiB manifest, 8 MiB package and expanded catalogue, 64 KiB per
// member, member count equal to the descriptor's rule count); the caps bound
// what survives parsing into stored state.

// defaultFeedSourceRuleLimit matches the package format bound so that default
// deployments keep the previous behaviour exactly: a source could already hold
// at most the whole 2000-entry catalogue.
const defaultFeedSourceRuleLimit = maxPackedCatalogueRules

// maxCommunityRuleBudget caps COMMUNITY_RULE_BUDGET. Each stored catalogue
// row carries its rule spec plus metadata (a 64 KiB member at most; typically
// a few kilobytes), so the knob trades catalogue coverage for storage and
// sync work, roughly linearly.
const maxCommunityRuleBudget = 20000

// defaultCommunityRuleBudget preserves the previous fixed catalogue capacity.
const defaultCommunityRuleBudget = 2000

// feedSourceRuleLimit resolves the enforced per-source cap: the configured
// value when it is in range, otherwise the default. Configs built directly
// (tests, bare App literals) carry the zero value and get the default.
func (a *App) feedSourceRuleLimit() int {
	if a.cfg.FeedSourceRuleLimit >= 1 && a.cfg.FeedSourceRuleLimit <= maxPackedCatalogueRules {
		return a.cfg.FeedSourceRuleLimit
	}
	return defaultFeedSourceRuleLimit
}

// communityRuleBudget resolves the enforced workspace-wide budget the same way.
func (a *App) communityRuleBudget() int {
	if a.cfg.CommunityRuleBudget >= 1 && a.cfg.CommunityRuleBudget <= maxCommunityRuleBudget {
		return a.cfg.CommunityRuleBudget
	}
	return defaultCommunityRuleBudget
}

// growthLimits carries the enforced caps through an import. A nil value skips
// enforcement and is used only for the bundled baseline seeded at first start.
type growthLimits struct {
	sourceLimit int
	budget      int
}

func (a *App) growthLimits() *growthLimits {
	return &growthLimits{sourceLimit: a.feedSourceRuleLimit(), budget: a.communityRuleBudget()}
}

// checkCatalogueGrowth enforces both caps for a workspace catalogue source
// inside the import transaction, after the new rows are written and before
// the caller commits. Counting stored rows (available or not) matches the
// storage the cap bounds: removed entries keep consuming capacity until their
// source is removed. before/totalBefore are the counts captured before the
// rows were mutated, which is what makes the cap a growth bound instead of a
// hard ceiling on incumbents.
func checkCatalogueGrowth(ctx context.Context, tx pgx.Tx, id int64, limits *growthLimits, before, totalBefore int) error {
	if limits == nil {
		return nil
	}
	var stored, total int
	if e := tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM rule_catalog WHERE feed_id=$1),(SELECT count(*) FROM rule_catalog)", id).Scan(&stored, &total); e != nil {
		return e
	}
	if stored > limits.sourceLimit && stored > before {
		return invalid(fmt.Sprintf("source rule cap reached: this release would grow the source from %d to %d stored rules, over the per-source rule cap of %d (RULE_FEED_SOURCE_LIMIT); the previous catalogue stays applied", before, stored, limits.sourceLimit))
	}
	if total > limits.budget && total > totalBefore {
		return invalid(fmt.Sprintf("community rule budget reached: this release would grow the workspace catalogue from %d to %d stored rules, over the budget of %d (COMMUNITY_RULE_BUDGET); remove unused sources or raise the budget; the previous catalogue stays applied", totalBefore, total, limits.budget))
	}
	return nil
}

// checkSiteFeedGrowth enforces the per-source cap for an application-scoped
// feed's staged candidates inside the import transaction. Rotating entry IDs
// grows staged storage even at a constant document size, so the bound is the
// stored row count, not the document's rule count.
func checkSiteFeedGrowth(ctx context.Context, tx pgx.Tx, id int64, limits *growthLimits, before int) error {
	if limits == nil {
		return nil
	}
	var staged int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM rule_feed_items WHERE feed_id=$1", id).Scan(&staged); e != nil {
		return e
	}
	if staged > limits.sourceLimit && staged > before {
		return invalid(fmt.Sprintf("source rule cap reached: this sync would grow the source from %d to %d staged rules, over the per-source rule cap of %d (RULE_FEED_SOURCE_LIMIT); the previous candidates stay available", before, staged, limits.sourceLimit))
	}
	return nil
}
