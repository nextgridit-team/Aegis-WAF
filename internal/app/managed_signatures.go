package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	conf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jcchavezs/mergefs"
)

const maxSignatureBundleBytes = 8 << 20

type managedSignatureOptions struct {
	SetID      string `json:"set_id"`
	Mode       string `json:"mode"`
	Paranoia   int    `json:"paranoia_level"`
	Threshold  int    `json:"inbound_threshold"`
	BodyLimit  int    `json:"body_limit_bytes"`
	Exclusions []int  `json:"excluded_rule_ids"`
}
type signatureSet struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Digest    string      `json:"digest"`
	RuleCount int         `json:"rule_count"`
	Files     signatureFS `json:"files,omitempty"`
}
type managedSignatureRuntime struct {
	Options managedSignatureOptions
	Set     signatureSet
	WAF     coraza.WAF
}
type managedSignatureResult struct {
	SetID      string `json:"set_id,omitempty"`
	Version    string `json:"version,omitempty"`
	Mode       string `json:"mode,omitempty"`
	RuleIDs    []int  `json:"rule_ids,omitempty"`
	Matches    int    `json:"matched_count,omitempty"`
	Inspection string `json:"inspection,omitempty"`
}

var signatureIDPattern = regexp.MustCompile(`\bid\s*:\s*([0-9]+)`)
var bundledSetOnce sync.Once
var bundledSet signatureSet
var bundledSetError error

func normalizeManagedSignatures(o managedSignatureOptions) (managedSignatureOptions, error) {
	if o.Mode == "" {
		o.Mode = "off"
	}
	if o.Mode != "off" && o.Mode != "observe" && o.Mode != "block" {
		return o, invalid("managed signature mode must be off, observe or block")
	}
	if o.Paranoia == 0 {
		o.Paranoia = 1
	}
	if o.Threshold == 0 {
		o.Threshold = 5
	}
	if o.BodyLimit == 0 {
		o.BodyLimit = 64 << 10
	}
	if o.Paranoia < 1 || o.Paranoia > 4 || o.Threshold < 1 || o.Threshold > 100 || o.BodyLimit < 4096 || o.BodyLimit > 1<<20 {
		return o, invalid("provide signature paranoia 1–4, threshold 1–100 and body limit 4096–1048576 bytes")
	}
	if len(o.SetID) > 128 || (o.Mode != "off" && o.SetID == "") {
		return o, invalid("load and select a managed signature set")
	}
	if len(o.Exclusions) > 100 {
		return o, invalid("at most 100 managed rule exclusions")
	}
	ids := map[int]bool{}
	out := []int{}
	for _, id := range o.Exclusions {
		if id < 900000 || id > 999999 {
			return o, invalid("excluded rule IDs must be CRS rule IDs")
		}
		if !ids[id] {
			ids[id] = true
			out = append(out, id)
		}
	}
	sort.Ints(out)
	o.Exclusions = out
	return o, nil
}
func effectiveManagedOptions(o managedSignatureOptions, policyMode string) managedSignatureOptions {
	if policyMode == "off" || o.Mode == "" {
		o.Mode = "off"
	} else if policyMode == "observe" && o.Mode == "block" {
		o.Mode = "observe"
	}
	return o
}
func signatureIDs(files signatureFS) map[int]bool {
	out := map[int]bool{}
	for name, data := range files {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		lines := []string{}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				lines = append(lines, line)
			}
		}
		for _, match := range signatureIDPattern.FindAllStringSubmatch(strings.Join(lines, "\n"), -1) {
			id, _ := strconv.Atoi(match[1])
			out[id] = true
		}
	}
	return out
}
func validateSignatureFiles(files signatureFS) (string, int, error) {
	if len(files) == 0 || len(files) > 256 {
		return "", 0, errors.New("invalid signature bundle file count")
	}
	size := 0
	for name, data := range files {
		if !fs.ValidPath(name) || name == "." || (!strings.HasPrefix(name, "@owasp_crs/") && name != "@coraza.conf-recommended" && name != "@crs-setup.conf.example" && name != "@crs-setup.conf.example-nodefaultact" && name != "LICENSE" && name != "NOTICE") {
			return "", 0, fmt.Errorf("invalid signature bundle path: %s", name)
		}
		size += len(data)
		if len(data) > 2<<20 || size > maxSignatureBundleBytes {
			return "", 0, errors.New("signature bundle size exceeded")
		}
	}
	for _, required := range []string{"@coraza.conf-recommended", "@crs-setup.conf.example"} {
		if _, ok := files[required]; !ok {
			return "", 0, errors.New("signature bundle configuration missing")
		}
	}
	raw, e := json.Marshal(files)
	if e != nil {
		return "", 0, e
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), len(signatureIDs(files)), nil
}
func bundledSignatureSet() (signatureSet, error) {
	bundledSetOnce.Do(func() {
		files := signatureFS{}
		source := mergefs.Merge(crs.FS, conf.FS)
		e := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if entry.IsDir() {
				return nil
			}
			data, e := fs.ReadFile(source, name)
			if e != nil {
				return e
			}
			files[name] = data
			return nil
		})
		if e != nil {
			bundledSetError = e
			return
		}
		digest, count, e := validateSignatureFiles(files)
		if e != nil {
			bundledSetError = e
			return
		}
		bundledSet = signatureSet{ID: "owasp-crs-" + crs.Version + "-" + digest[:12], Name: "OWASP Core Rule Set", Version: crs.Version, Digest: digest, RuleCount: count, Files: files}
	})
	return bundledSet, bundledSetError
}
func readSignatureSet(ctx context.Context, tx pgx.Tx, id string) (signatureSet, error) {
	var set signatureSet
	var raw []byte
	e := tx.QueryRow(ctx, "SELECT id,name,version,digest,rule_count,files FROM signature_sets WHERE id=$1", id).Scan(&set.ID, &set.Name, &set.Version, &set.Digest, &set.RuleCount, &raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return set, invalid("managed signature set is not loaded")
	}
	if e != nil {
		return set, e
	}
	if e = json.Unmarshal(raw, &set.Files); e != nil {
		return set, e
	}
	digest, count, e := validateSignatureFiles(set.Files)
	if e != nil {
		return set, e
	}
	if digest != set.Digest || count != set.RuleCount {
		return set, errors.New("signature bundle integrity check failed")
	}
	return set, nil
}
func compileManagedSignatures(set signatureSet, options managedSignatureOptions) (*managedSignatureRuntime, error) {
	options, e := normalizeManagedSignatures(options)
	if e != nil {
		return nil, e
	}
	known := signatureIDs(set.Files)
	for _, id := range options.Exclusions {
		if !known[id] {
			return nil, invalid(fmt.Sprintf("rule %d is not in this signature set", id))
		}
	}
	engineMode := "DetectionOnly"
	limitAction := "ProcessPartial"
	if options.Mode == "block" {
		engineMode = "On"
		limitAction = "Reject"
	}
	settings := fmt.Sprintf("SecRuleEngine %s\nSecAuditEngine Off\nSecDebugLogLevel 0\nSecResponseBodyAccess Off\nSecRequestBodyAccess On\nSecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyInMemoryLimit %d\nSecRequestBodyLimitAction %s\nSecAction \"id:100000,phase:1,pass,nolog,t:none,setvar:tx.paranoia_level=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d\"", engineMode, options.BodyLimit, options.BodyLimit, options.BodyLimit, limitAction, options.Paranoia, options.Paranoia, options.Threshold)
	configuration := coraza.NewWAFConfig().WithRootFS(set.Files).WithDebugLogger(debuglog.Noop()).WithErrorCallback(func(types.MatchedRule) {}).WithDirectivesFromFile("@coraza.conf-recommended").WithDirectivesFromFile("@crs-setup.conf.example").WithDirectives(settings).WithDirectivesFromFile("@owasp_crs/REQUEST-*.conf")
	if len(options.Exclusions) > 0 {
		ids := []string{}
		for _, id := range options.Exclusions {
			ids = append(ids, strconv.Itoa(id))
		}
		configuration = configuration.WithDirectives("SecRuleRemoveById " + strings.Join(ids, " "))
	}
	waf, e := coraza.NewWAF(configuration)
	if e != nil {
		return nil, invalid("managed signature configuration could not compile")
	}
	return &managedSignatureRuntime{Options: options, Set: set, WAF: waf}, nil
}
func managedRuntimeKey(o managedSignatureOptions) string {
	raw, _ := json.Marshal(o)
	return string(raw)
}
func (a *App) loadManagedSignatures(ctx context.Context, tx pgx.Tx, next *snapshot) error {
	next.managedSets = map[string]signatureSet{}
	next.managedWAFs = map[string]*managedSignatureRuntime{}
	old := a.active.Load()
	for site, bindings := range next.policyBindings {
		for n := range bindings {
			binding := &bindings[n]
			options := binding.ManagedOptions
			if options.Mode == "off" || options.Mode == "" {
				continue
			}
			set, ok := next.managedSets[options.SetID]
			if !ok {
				var e error
				set, e = readSignatureSet(ctx, tx, options.SetID)
				if e != nil {
					return e
				}
				next.managedSets[set.ID] = set
			}
			key := managedRuntimeKey(options)
			runtime := next.managedWAFs[key]
			if runtime == nil && old != nil {
				runtime = old.managedWAFs[key]
			}
			if runtime == nil {
				if len(next.managedWAFs) >= 8 {
					return errors.New("at most eight active managed signature configurations per replica")
				}
				var e error
				runtime, e = compileManagedSignatures(set, options)
				if e != nil {
					return e
				}
			}
			next.managedWAFs[key] = runtime
			binding.Managed = runtime
		}
		next.policyBindings[site] = bindings
	}
	return nil
}
func signatureAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/signature-sets/{id}/rules", a.wrap(true, a.signatureInventory))
	m.HandleFunc("GET /api/signature-sets", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, "SELECT id,name,version,digest,rule_count,created_at FROM signature_sets ORDER BY created_at,id")
	}))
	m.HandleFunc("GET /api/signature-sets/catalogue", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		set, e := bundledSignatureSet()
		if e != nil {
			return e
		}
		var loaded bool
		if e = a.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM signature_sets WHERE id=$1)", set.ID).Scan(&loaded); e != nil {
			return e
		}
		set.Files = nil
		respond(w, 200, []any{map[string]any{"set": set, "loaded": loaded, "engine": "Coraza", "engine_version": "3.8.1", "scope": "request headers and bounded request bodies"}})
		return nil
	}))
	m.HandleFunc("POST /api/signature-sets", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		var input struct {
			ID string `json:"id"`
		}
		if e := decode(w, r, &input); e != nil {
			return e
		}
		set, e := bundledSignatureSet()
		if e != nil {
			return e
		}
		if input.ID != set.ID {
			return invalid("choose a bundled signature set from the catalogue")
		}
		raw, _ := json.Marshal(set.Files)
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			tag, e := tx.Exec(r.Context(), "INSERT INTO signature_sets(id,name,version,digest,rule_count,files) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING", set.ID, set.Name, set.Version, set.Digest, set.RuleCount, raw)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 0 {
				return nil
			}
			return audit(r.Context(), tx, i.Username, "signature_set.loaded", set.ID)
		})
		if e != nil {
			return e
		}
		set.Files = nil
		respond(w, 200, set)
		return nil
	}))
}
