package app

import (
	"context"
	"errors"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jackc/pgx/v5"
)

type signatureEntry struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Phase    int      `json:"phase"`
	Paranoia int      `json:"paranoia_level"`
	Tags     []string `json:"tags"`
	Source   string   `json:"source"`
	Scope    string   `json:"scope"`
}

// Only static corpus metadata is retained. Raw directives, request data and WAF
// instances are not retained by the management inventory cache.
var signatureInventories = struct {
	sync.Mutex
	entries map[string][]signatureEntry
	order   []string
}{entries: map[string][]signatureEntry{}}
var signatureMessage = regexp.MustCompile(`(?i)(?:^|[,\s])msg\s*:\s*'((?:\\.|[^'\\])*)'`)

func signatureCategory(file string) string {
	name := strings.TrimSuffix(path.Base(file), ".conf")
	parts := strings.SplitN(name, "-", 3)
	if len(parts) == 3 {
		name = parts[2]
	}
	return strings.ReplaceAll(name, "-", " ")
}
func inventoryForSignatures(set signatureSet) ([]signatureEntry, error) {
	signatureInventories.Lock()
	defer signatureInventories.Unlock()
	if entries, ok := signatureInventories.entries[set.Digest]; ok {
		return entries, nil
	}
	entries := []signatureEntry{}
	seen := map[int]bool{}
	known := signatureIDs(set.Files)
	configuration := coraza.NewWAFConfig().WithRootFS(set.Files).WithDebugLogger(debuglog.Noop()).WithErrorCallback(func(types.MatchedRule) {}).
		WithDirectivesFromFile("@coraza.conf-recommended").WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectives("SecRuleEngine DetectionOnly\nSecAuditEngine Off\nSecDebugLogLevel 0\nSecResponseBodyAccess Off").WithDirectivesFromFile("@owasp_crs/*.conf")
	configuration = experimental.WAFConfigWithRuleObserver(configuration, func(rule types.RuleMetadata) {
		id := rule.ID()
		if !known[id] || seen[id] {
			return
		}
		seen[id] = true
		name := "CRS support rule"
		if match := signatureMessage.FindStringSubmatch(rule.Raw()); len(match) > 1 {
			name = strings.ReplaceAll(strings.ReplaceAll(match[1], `\'`, `'`), `\\`, `\`)
		}
		tags := append([]string{}, rule.Tags()...)
		paranoia := 0
		for _, tag := range tags {
			if strings.HasPrefix(tag, "paranoia-level/") {
				paranoia, _ = strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/"))
			}
		}
		phase := int(rule.Phase())
		scope := "request"
		if id < 910000 {
			scope = "setup"
		} else if phase > 2 {
			scope = "response"
		}
		entries = append(entries, signatureEntry{ID: id, Name: name, Category: signatureCategory(rule.File()), Severity: rule.Severity().String(), Phase: phase, Paranoia: paranoia, Tags: tags, Source: path.Base(rule.File()), Scope: scope})
	})
	waf, e := coraza.NewWAF(configuration)
	if e != nil {
		return nil, errors.New("could not read managed signature inventory")
	}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		defer closer.Close()
	}
	if len(entries) == 0 || len(entries) > 4096 {
		return nil, errors.New("managed signature inventory exceeds supported bounds")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if len(signatureInventories.order) >= 8 {
		delete(signatureInventories.entries, signatureInventories.order[0])
		signatureInventories.order = signatureInventories.order[1:]
	}
	signatureInventories.order = append(signatureInventories.order, set.Digest)
	signatureInventories.entries[set.Digest] = entries
	return entries, nil
}

func (a *App) signatureInventory(w http.ResponseWriter, r *http.Request, _ identity) error {
	id := r.PathValue("id")
	if len(id) > 128 {
		return invalid("invalid signature set identifier")
	}
	tx, e := a.db.BeginTx(r.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	var loaded bool
	if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM signature_sets WHERE id=$1)", id).Scan(&loaded); e != nil {
		return e
	}
	var set signatureSet
	if loaded {
		set, e = readSignatureSet(r.Context(), tx, id)
	} else {
		set, e = bundledSignatureSet()
		if e == nil && set.ID != id {
			return apiError{404, "signature set not found"}
		}
	}
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	entries, e := inventoryForSignatures(set)
	if e != nil {
		return e
	}
	set.Files = nil
	// JSON is immutable corpus metadata, never live matched data or directives.
	result := struct {
		Set    signatureSet     `json:"set"`
		Loaded bool             `json:"loaded"`
		Rules  []signatureEntry `json:"rules"`
	}{set, loaded, entries}
	respond(w, 200, result)
	return nil
}
