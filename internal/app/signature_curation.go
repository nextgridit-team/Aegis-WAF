package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/semver"
)

type signatureCuration struct {
	SourceID      string `json:"source_set_id"`
	SourceVersion string `json:"source_version"`
	SourceDigest  string `json:"source_digest"`
	Selected      []int  `json:"selected_rule_ids"`
}

// Keep initialization, anomaly evaluation, reporting and non-detection helpers.
// Removing these would leave selected detectors unable to enforce their scores.
func selectableSignature(entry signatureEntry) bool {
	return entry.HasMessage && ((entry.ID >= 910000 && entry.ID < 949000) || (entry.ID >= 950000 && entry.ID < 959000))
}
func curateSignatures(source signatureSet, name string, selected []int) (signatureSet, error) {
	var result signatureSet
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 || strings.ContainsAny(name, "\r\n") || source.Curation != nil || len(selected) < 1 || len(selected) > 4096 {
		return result, invalid("provide a name and detection rules from one original installed source set")
	}
	entries, e := inventoryForSignatures(source)
	if e != nil {
		return result, e
	}
	eligible := map[int]bool{}
	for _, entry := range entries {
		if selectableSignature(entry) {
			eligible[entry.ID] = true
		}
	}
	chosen := map[int]bool{}
	ids := append([]int{}, selected...)
	for _, id := range ids {
		if !eligible[id] || chosen[id] {
			return result, invalid("selection must contain unique detection rule IDs from the source")
		}
		chosen[id] = true
	}
	sort.Ints(ids)
	result = signatureSet{Name: name, Version: source.Version, Files: signatureFS{}, Curation: &signatureCuration{SourceID: source.ID, SourceVersion: source.Version, SourceDigest: source.Digest, Selected: ids}}
	for file, content := range source.Files {
		result.Files[file] = append([]byte{}, content...)
	}
	request, response := []int{}, []int{}
	for _, entry := range entries {
		if !eligible[entry.ID] || chosen[entry.ID] {
			continue
		}
		if entry.Scope == "response" {
			response = append(response, entry.ID)
		} else {
			request = append(request, entry.ID)
		}
	}
	for _, part := range []struct {
		name string
		ids  []int
	}{{"REQUEST", request}, {"RESPONSE", response}} {
		if len(part.ids) == 0 {
			continue
		}
		values := []string{}
		for _, id := range part.ids {
			values = append(values, strconv.Itoa(id))
		}
		result.Files["@owasp_crs/"+part.name+"-9999-AEGIS-CURATION.conf"] = []byte("# Immutable Aegis selection; CRS support rules are retained.\nSecRuleRemoveById " + strings.Join(values, " ") + "\n")
	}
	result.Digest, result.RuleCount, e = validateSignatureFiles(result.Files)
	if e != nil {
		return result, e
	}
	provenance, _ := json.Marshal(struct {
		Name   string
		Digest string
		Source *signatureCuration
	}{result.Name, result.Digest, result.Curation})
	sum := sha256.Sum256(provenance)
	result.ID = "curated-" + hex.EncodeToString(sum[:16])
	// Compile both directions before storing. This validates overlays and mandatory
	// helpers without modifying a live policy or introducing another engine path.
	compiled, e := compileManagedSignatures(result, managedSignatureOptions{SetID: result.ID, Mode: "observe", ResponseMode: "observe"})
	if e != nil {
		return signatureSet{}, invalid("curated signature set could not compile")
	}
	closeManagedRuntime(compiled)
	return result, nil
}
func closeManagedRuntime(runtime *managedSignatureRuntime) {
	// Release the short-lived engines used to validate an artifact before storing it.
	for _, waf := range []any{runtime.WAF, runtime.StreamWAF} {
		if closer, ok := waf.(experimental.WAFCloser); ok {
			_ = closer.Close()
		}
	}
}

func (a *App) createCuratedSet(w http.ResponseWriter, r *http.Request, who identity, name, sourceID string, selected []int) error {
	var set signatureSet
	e := a.change(r.Context(), func(tx pgx.Tx) error {
		source, e := readSignatureSet(r.Context(), tx, sourceID)
		if e != nil {
			return e
		}
		set, e = curateSignatures(source, name, selected)
		if e != nil {
			return e
		}
		var count int
		if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM signature_sets WHERE curation IS NOT NULL").Scan(&count); e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM signature_sets WHERE id=$1)", set.ID).Scan(&exists); e != nil {
			return e
		}
		if count >= 64 && !exists {
			return invalid("at most 64 immutable curated signature sets are supported")
		}
		files, _ := json.Marshal(set.Files)
		provenance, _ := json.Marshal(set.Curation)
		tag, e := tx.Exec(r.Context(), "INSERT INTO signature_sets(id,name,version,digest,rule_count,files,curation) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING", set.ID, set.Name, set.Version, set.Digest, set.RuleCount, files, provenance)
		if e != nil {
			return e
		}
		if tag.RowsAffected() > 0 {
			return audit(r.Context(), tx, who.Username, "signature_set.curated", set.ID)
		}
		return nil
	})
	if e != nil {
		return e
	}
	set.Files = nil
	respond(w, 200, set)
	return nil
}

type signatureSourceUpdate struct {
	Source    signatureSet `json:"source"`
	Changed   []int        `json:"changed_rule_ids"`
	Removed   []int        `json:"removed_rule_ids"`
	Available bool         `json:"available"`
}

func signatureUpdates(frozen, source, latest signatureSet) (signatureSourceUpdate, error) {
	current := latest
	latest.Files = nil
	result := signatureSourceUpdate{Source: latest, Changed: []int{}, Removed: []int{}}
	if frozen.Curation == nil || frozen.Curation.SourceID == latest.ID {
		return result, nil
	}
	// Aegis currently installs versioned bundled CRS sources, not arbitrary remote
	// SecLang feeds. Only compare another original source with the same identity.
	if latest.Name != source.Name || (semver.IsValid("v"+strings.TrimPrefix(latest.Version, "v")) && semver.IsValid("v"+strings.TrimPrefix(source.Version, "v")) && semver.Compare("v"+strings.TrimPrefix(latest.Version, "v"), "v"+strings.TrimPrefix(source.Version, "v")) < 0) {
		return result, nil
	}
	entries, e := inventoryForSignatures(current)
	if e != nil {
		return result, e
	}
	known := map[int]signatureEntry{}
	for _, entry := range entries {
		known[entry.ID] = entry
	}
	old, e := inventoryForSignatures(source)
	if e != nil {
		return result, e
	}
	oldKnown := map[int]signatureEntry{}
	for _, entry := range old {
		oldKnown[entry.ID] = entry
	}
	// A retained setup, scoring or control rule can affect every selected detector.
	// Use both inventories so added or removed helper sources also trigger review.
	detectorSources, helperSources := map[string]bool{}, map[string]bool{}
	for _, inventory := range [][]signatureEntry{old, entries} {
		for _, entry := range inventory {
			file := "@owasp_crs/" + entry.Source
			if selectableSignature(entry) {
				detectorSources[file] = true
			} else {
				helperSources[file] = true
			}
		}
	}
	sharedFile := func(file string) bool {
		return strings.HasSuffix(file, ".data") || !strings.HasPrefix(file, "@owasp_crs/") ||
			(strings.HasSuffix(file, ".conf") && (helperSources[file] || !detectorSources[file]))
	}
	sharedChanged := false
	for file, content := range source.Files {
		if sharedFile(file) {
			if !bytes.Equal(content, current.Files[file]) {
				sharedChanged = true
			}
		}
	}
	for file, content := range current.Files {
		if sharedFile(file) {
			if !bytes.Equal(content, source.Files[file]) {
				sharedChanged = true
			}
		}
	}
	for _, id := range frozen.Curation.Selected {
		entry, ok := known[id]
		if !ok || !selectableSignature(entry) {
			result.Removed = append(result.Removed, id)
			continue
		}
		oldEntry := oldKnown[id]
		// File-level comparison is deliberately conservative: changed chains or shared
		// data can affect a rule even when its top-level message did not change.
		if sharedChanged || oldEntry.Source != entry.Source || !bytes.Equal(source.Files["@owasp_crs/"+oldEntry.Source], current.Files["@owasp_crs/"+entry.Source]) {
			result.Changed = append(result.Changed, id)
		}
	}
	result.Available = true
	return result, nil
}
func (a *App) signatureSetUpdates(w http.ResponseWriter, r *http.Request, _ identity) error {
	tx, e := a.db.BeginTx(r.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	frozen, e := readSignatureSet(r.Context(), tx, r.PathValue("id"))
	if e != nil {
		return e
	}
	if frozen.Curation == nil {
		return invalid("choose a curated signature set")
	}
	source, e := readSignatureSet(r.Context(), tx, frozen.Curation.SourceID)
	if e != nil {
		return e
	}
	latest, e := bundledSignatureSet()
	if e != nil {
		return e
	}
	result, e := signatureUpdates(frozen, source, latest)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, result)
	return nil
}
