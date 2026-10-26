package app

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// Initialization is serialized by the schema advisory lock. The marker survives
// deletion, so an administrator's edits/deletion are never undone on restart.
func seedBaselinePolicy(ctx context.Context, tx pgx.Tx) error {
	var seeded bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM built_in_policies WHERE key='baseline-protection')").Scan(&seeded); e != nil {
		return e
	}
	if seeded {
		return nil
	}
	if _, e := tx.Exec(ctx, "SELECT version FROM config_version WHERE id FOR UPDATE"); e != nil {
		return e
	}
	set, e := bundledSignatureSet()
	if e != nil {
		return e
	}
	files, e := json.Marshal(set.Files)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO signature_sets(id,name,version,digest,rule_count,files) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING", set.ID, set.Name, set.Version, set.Digest, set.RuleCount, files); e != nil {
		return e
	}
	spec := policySpec{Name: "Baseline protection", Description: "Included OWASP CRS request protection: Block, paranoia level 1, anomaly threshold 5, 1 MiB request-body limit. Bot and flood controls are off until tuned for the application. Assign explicitly; existing applications are not changed.", Mode: "block", ManagedSignatures: managedSignatureOptions{SetID: set.ID, Mode: "block", Paranoia: 1, Threshold: 5, BodyLimit: 1 << 20, Exclusions: []int{}}, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroup{}}
	spec.BotChallenge, e = normalizeBotChallenge(spec.BotChallenge)
	if e != nil {
		return e
	}
	spec.ManagedSignatures, e = normalizeManagedSignatures(spec.ManagedSignatures)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(spec)
	if e != nil {
		return e
	}
	var id int64
	if e = tx.QueryRow(ctx, "INSERT INTO policies(spec) VALUES($1) RETURNING id", raw).Scan(&id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) VALUES($1,1,$2,'system')", id, raw); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO built_in_policies(key,policy_id) VALUES('baseline-protection',$1)", id); e != nil {
		return e
	}
	if e = audit(ctx, tx, "system", "policy.baseline_created", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id")
	return e
}
