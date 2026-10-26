package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

type policyFeedRule struct {
	CVEs     []string `json:"cves"`
	FeedID   int64    `json:"feed_id"`
	EntryID  string   `json:"entry_id"`
	Revision int      `json:"revision"`
	Digest   string   `json:"digest"`
	Pack     string   `json:"pack"`
}

func (a *App) readPolicyLibraryRule(ctx context.Context, tx pgx.Tx, id int64) (policyRule, error) {
	record, e := readRule(ctx, tx, id, false)
	if e == nil {
		record.Spec.EvidenceIDs = nil
		return policyRule{RuleID: id, Spec: record.Spec}, nil
	}
	var api apiError
	if !errors.As(e, &api) || api.status != 404 {
		return policyRule{}, e
	}
	var raw, metadata []byte
	var feed policyFeedRule
	e = tx.QueryRow(ctx, "SELECT spec,metadata,feed_id,entry_id,revision,digest FROM rule_catalog WHERE id=$1 AND available", id).Scan(&raw, &metadata, &feed.FeedID, &feed.EntryID, &feed.Revision, &feed.Digest)
	if errors.Is(e, pgx.ErrNoRows) {
		return policyRule{}, invalid("selected rule is missing or no longer available; retain its pinned snapshot or remove it")
	}
	if e != nil {
		return policyRule{}, e
	}
	var spec RuleSpec
	var meta catalogueMetadata
	if e = json.Unmarshal(raw, &spec); e != nil {
		return policyRule{}, e
	}
	if e = json.Unmarshal(metadata, &meta); e != nil {
		return policyRule{}, e
	}
	feed.Pack = meta.Pack
	feed.CVEs = meta.CVEs
	return policyRule{RuleID: id, Spec: spec, Feed: &feed}, nil
}
func commitCatalogue(ctx context.Context, tx pgx.Tx, id int64, manifest ruleManifest, items []catalogueCandidate) error {
	var previous int
	var oldDigest string
	if e := tx.QueryRow(ctx, "SELECT manifest_revision,manifest_digest FROM rule_feeds WHERE id=$1", id).Scan(&previous, &oldDigest); e != nil {
		return e
	}
	raw, _ := json.Marshal(manifest)
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	if manifest.Revision < previous || (manifest.Revision == previous && oldDigest != "" && oldDigest != digest) {
		return invalid("manifest revision rollback or conflicting contents; publisher must increment revision")
	}
	for _, item := range items {
		var oldRevision int
		var priorDigest string
		e := tx.QueryRow(ctx, "SELECT revision,digest FROM rule_catalog WHERE feed_id=$1 AND entry_id=$2", id, item.File.ID).Scan(&oldRevision, &priorDigest)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil && (item.File.Revision < oldRevision || (item.File.Revision == oldRevision && priorDigest != item.Digest)) {
			return invalid("rule revision rollback or conflicting contents; publisher must increment revision")
		}
	}
	if _, e := tx.Exec(ctx, "UPDATE rule_catalog SET available=false WHERE feed_id=$1", id); e != nil {
		return e
	}
	for _, item := range items {
		spec, _ := json.Marshal(item.File.Rule)
		meta, _ := json.Marshal(item.File.catalogueMetadata)
		if _, e := tx.Exec(ctx, "INSERT INTO rule_catalog(feed_id,entry_id,revision,digest,spec,metadata) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(feed_id,entry_id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,spec=excluded.spec,metadata=excluded.metadata,available=true,updated_at=now()", id, item.File.ID, item.File.Revision, item.Digest, spec, meta); e != nil {
			return e
		}
	}
	var count int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM rule_catalog").Scan(&count); e != nil {
		return e
	}
	if count > 2000 {
		return invalid("catalogue capacity reached (2000 entries); remove unused sources")
	}
	if _, e := tx.Exec(ctx, "UPDATE rule_feeds SET manifest_revision=$2,manifest_digest=$3 WHERE id=$1", id, manifest.Revision, digest); e != nil {
		return e
	}
	// Policy application and MCP receipts depend on catalogue definitions. Serialize
	// with config writes so a sync cannot replace a simulated rule before publish.
	if digest != oldDigest {
		_, e := tx.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id")
		return e
	}
	return nil
}
func catalogueAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/rule-catalog", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, `SELECT c.id,c.feed_id,c.entry_id,c.revision,c.digest,c.spec,c.metadata->>'pack' AS pack,c.metadata->'cves' AS cves,f.name AS feed_name,c.available FROM rule_catalog c JOIN rule_feeds f ON f.id=c.feed_id WHERE c.available ORDER BY c.id`)
	}))
}
func (a *App) listCatalogueItems(w http.ResponseWriter, r *http.Request, id int64) error {
	return a.list(w, r, `SELECT c.id AS catalog_id,c.entry_id,c.revision,c.digest,c.spec,c.metadata,c.available,
 coalesce((SELECT jsonb_agg(jsonb_build_object('id',p.id,'name',p.spec->>'name','revision',r->'feed'->'revision','update_available',(r->'feed'->>'digest') IS DISTINCT FROM c.digest)) FROM policies p CROSS JOIN LATERAL jsonb_array_elements(p.spec->'groups') g CROSS JOIN LATERAL jsonb_array_elements(g->'rules') r WHERE (r->>'rule_id')::bigint=c.id),'[]') AS policies
 FROM rule_catalog c WHERE c.feed_id=`+strconv.FormatInt(id, 10)+` ORDER BY c.entry_id`)
}
