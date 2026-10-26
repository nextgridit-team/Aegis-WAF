package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type detailedCustomRule struct {
	RuleResult
	Name             string    `json:"name"`
	DefinitionSource string    `json:"definition_source"`
	Definition       *RuleSpec `json:"definition,omitempty"`
}

func (a *App) requestDetails(w http.ResponseWriter, r *http.Request, _ identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	tx, e := a.db.BeginTx(r.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	var raw, evidence []byte
	var siteName *string
	var domains []string
	var evidenceExpires *time.Time
	e = tx.QueryRow(r.Context(), `SELECT to_jsonb(l),s.name,s.hostnames,CASE WHEN e.expires_at>now() THEN e.data END,e.expires_at FROM access_logs l LEFT JOIN sites s ON s.id=l.site_id LEFT JOIN traffic_evidence e ON e.id=l.event_id AND e.site_id=l.site_id WHERE l.id=$1`, id).Scan(&raw, &siteName, &domains, &evidence, &evidenceExpires)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{404, "request log not found"}
	}
	if e != nil {
		return e
	}
	names, e := loadAddressNames(r.Context(), tx)
	if e != nil {
		return e
	}
	raw, e = names.annotate(raw)
	if e != nil {
		return e
	}
	var event struct {
		PolicyID       int64                  `json:"policy_id"`
		PolicyRevision int64                  `json:"policy_revision"`
		EventID        string                 `json:"event_id"`
		Results        []RuleResult           `json:"rule_results"`
		Managed        managedSignatureResult `json:"managed_signatures"`
	}
	if e = json.Unmarshal(raw, &event); e != nil {
		return e
	}
	var policyRaw []byte
	var frozen policySpec
	if event.PolicyID > 0 {
		e = tx.QueryRow(r.Context(), "SELECT spec FROM policy_revisions WHERE policy_id=$1 AND revision=$2", event.PolicyID, event.PolicyRevision).Scan(&policyRaw)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if len(policyRaw) > 0 {
			if e = json.Unmarshal(policyRaw, &frozen); e != nil {
				return e
			}
		}
	}
	definitions := map[int64]RuleSpec{}
	for _, group := range effectivePolicyGroups(frozen) {
		for _, rule := range group.Rules {
			definitions[rule.RuleID] = rule.Spec
		}
	}
	current := map[int64]RuleSpec{}
	ids := []int64{}
	for _, result := range event.Results {
		if _, ok := definitions[result.RuleID]; !ok {
			ids = append(ids, result.RuleID)
		}
	}
	if len(ids) > 0 {
		rows, e := tx.Query(r.Context(), "SELECT id,spec FROM rules WHERE id=ANY($1) UNION ALL SELECT id,spec FROM rule_catalog WHERE id=ANY($1)", ids)
		if e != nil {
			return e
		}
		for rows.Next() {
			var ruleID int64
			var ruleRaw []byte
			if e = rows.Scan(&ruleID, &ruleRaw); e != nil {
				rows.Close()
				return e
			}
			var spec RuleSpec
			if e = json.Unmarshal(ruleRaw, &spec); e != nil {
				rows.Close()
				return e
			}
			current[ruleID] = spec
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	custom := []detailedCustomRule{}
	for _, result := range event.Results {
		rule := detailedCustomRule{RuleResult: result, DefinitionSource: "unavailable"}
		if spec, ok := definitions[result.RuleID]; ok {
			rule.Name = spec.Name
			rule.Definition = &spec
			rule.DefinitionSource = "policy_snapshot"
		} else if spec, ok := current[result.RuleID]; ok {
			rule.Name = spec.Name
			rule.Definition = &spec
			rule.DefinitionSource = "current_library"
		}
		custom = append(custom, rule)
	}
	managed := []signatureEntry{}
	managedState := "not_evaluated"
	if event.Managed.SetID != "" {
		managedState = "available"
		set, err := readSignatureSet(r.Context(), tx, event.Managed.SetID)
		if err != nil {
			managedState = "unavailable"
		} else {
			entries, err := inventoryForSignatures(set)
			if err != nil {
				managedState = "unavailable"
			} else {
				matched := map[int]bool{}
				for _, id := range event.Managed.RuleIDs {
					matched[id] = true
				}
				for _, entry := range entries {
					if matched[entry.ID] {
						managed = append(managed, entry)
					}
				}
			}
		}
	}
	evidenceState := "not_captured"
	if event.EventID != "" {
		evidenceState = "expired_or_removed"
		if len(evidence) > 0 {
			evidenceState = "available"
		} else if evidenceExpires != nil {
			evidenceState = "expired"
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	var captured any
	if len(evidence) > 0 {
		captured = json.RawMessage(evidence)
	}
	var historical any
	if len(policyRaw) > 0 {
		historical = json.RawMessage(policyRaw)
	}
	respond(w, 200, map[string]any{"event": json.RawMessage(raw), "application": map[string]any{"name": siteName, "current_hostnames": domains}, "policy_snapshot": historical, "custom_rules": custom, "managed_rules": managed, "managed_metadata": managedState, "evidence": captured, "evidence_state": evidenceState, "evidence_expires_at": evidenceExpires})
	return nil
}
