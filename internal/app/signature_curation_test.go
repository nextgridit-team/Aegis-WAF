package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCuratedSignatureSelection(t *testing.T) {
	source, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	curated, e := curateSignatures(source, "SQL detection", []int{942100})
	if e != nil {
		t.Fatal(e)
	}
	if curated.Curation.SourceDigest != source.Digest || curated.Curation.SourceVersion != source.Version || curated.Digest == source.Digest {
		t.Fatal("missing frozen provenance")
	}
	entries, e := inventoryForSignatures(curated)
	if e != nil {
		t.Fatal(e)
	}
	selected, support := 0, false
	for _, entry := range entries {
		if entry.Selectable {
			selected++
			if entry.ID != 942100 {
				t.Fatal("unselected detection in curated inventory", entry.ID)
			}
		}
		support = support || entry.ID == 949110
	}
	if selected != 1 || !support {
		t.Fatal("selection or score enforcement helper missing", selected, support)
	}
	a := &App{managedSlots: make(chan struct{}, 64)}
	for _, mode := range []string{"observe", "block"} {
		runtime, e := compileManagedSignatures(curated, managedSignatureOptions{SetID: curated.ID, Mode: mode})
		if e != nil {
			t.Fatal(e)
		}
		defer closeManagedRuntime(runtime)
		for _, tc := range []struct {
			query  string
			attack bool
		}{{"chair", false}, {"1' UNION SELECT password FROM users --", true}, {"<script>alert(1)</script>", false}} {
			r := httptest.NewRequest("GET", "http://app.test/search?q="+url.QueryEscape(tc.query), nil)
			r.Header.Set("User-Agent", "browser")
			r.Header.Set("Accept", "text/html")
			result, blocked, _ := a.inspectManaged(runtime, r, netip.MustParseAddr("203.0.113.4"))
			if blocked != (tc.attack && mode == "block") {
				t.Fatalf("curated %s blocked=%v attack=%v result=%+v", mode, blocked, tc.attack, result)
			}
			for _, id := range result.RuleIDs {
				if id != 942100 && id < 949000 {
					t.Fatal("unselected detector ran", id)
				}
			}
		}
	}
	again, e := curateSignatures(source, "SQL detection", []int{942100})
	if e != nil || again.ID != curated.ID || again.Digest != curated.Digest {
		t.Fatal("nonreproducible artifact", e)
	}
	for _, ids := range [][]int{nil, {942100, 942100}, {949110}, {999999}} {
		if _, e := curateSignatures(source, "Bad", ids); e == nil {
			t.Fatal("invalid selection accepted", ids)
		}
	}
	if _, e := curateSignatures(curated, "Nested", []int{942100}); e == nil {
		t.Fatal("nested source accepted")
	}
	digest, _, _ := validateSignatureFiles(source.Files)
	if digest != source.Digest {
		t.Fatal("original source changed")
	}
}
func TestCuratedSourceReview(t *testing.T) {
	source, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	curated, e := curateSignatures(source, "Review SQL", []int{942100})
	if e != nil {
		t.Fatal(e)
	}
	result, e := signatureUpdates(curated, source, source)
	if e != nil || result.Available {
		t.Fatal("unchanged source reported as newer", e)
	}
	for _, filePart := range []string{"REQUEST-942-", "REQUEST-901-", "REQUEST-949-"} {
		t.Run(filePart, func(t *testing.T) {
			latest := source
			latest.ID = "future-source"
			latest.Version = "4.31.0"
			latest.Files = signatureFS{}
			changed := false
			for file, data := range source.Files {
				latest.Files[file] = data
				if strings.Contains(file, filePart) {
					latest.Files[file] = append(append([]byte{}, data...), []byte("\n# changed upstream chain, matcher or helper\n")...)
					changed = true
				}
			}
			if !changed {
				t.Fatal("regression fixture did not change a source file")
			}
			latest.Digest, latest.RuleCount, e = validateSignatureFiles(latest.Files)
			if e != nil {
				t.Fatal(e)
			}
			result, e := signatureUpdates(curated, source, latest)
			if e != nil || !result.Available || len(result.Changed) != 1 || result.Changed[0] != 942100 || len(result.Source.Files) != 0 {
				t.Fatal("changed file not flagged for conservative review", result, e)
			}
		})
	}
}
func TestCuratedSignatureIntegration(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	source, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	input := map[string]any{"name": "API SQL curated", "source_set_id": source.ID, "selected_rule_ids": []int{942100}}
	csrf := api.csrf
	api.csrf = "incorrect"
	api.call("POST", "/api/signature-sets", input, 403)
	api.csrf = csrf
	var curated signatureSet
	json.Unmarshal(api.call("POST", "/api/signature-sets", input, 200), &curated)
	if curated.Curation == nil || len(curated.Files) != 0 {
		t.Fatal("invalid public artifact", curated)
	}
	api.call("POST", "/api/signature-sets", input, 200)
	var count int
	a.db.QueryRow(ctx, "SELECT count(*) FROM signature_sets WHERE curation IS NOT NULL").Scan(&count)
	if count != 1 {
		t.Fatal("duplicate immutable set", count)
	}
	api.call("GET", "/api/signature-sets/"+curated.ID+"/updates", nil, 200)
	spec := policyInput{Spec: policySpecInput{Name: "Curated test", Mode: "observe", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{}, ManagedSignatures: managedSignatureOptions{SetID: curated.ID, Mode: "block"}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	policy := mustID(t, api.call("POST", "/api/policies", spec, 200))
	spec.Revision = 1
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		binding := replica.active.Load().policyBindings[site][0]
		if binding.Managed.Options.Mode != "observe" {
			t.Fatal("policy observe did not cap curated enforcement")
		}
	}
	var original []byte
	a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=$1", policy).Scan(&original)
	input["name"] = "Other selection"
	input["selected_rule_ids"] = []int{941100}
	api.call("POST", "/api/signature-sets", input, 200)
	var frozen []byte
	a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=$1", policy).Scan(&frozen)
	if string(frozen) != string(original) {
		t.Fatal("library creation changed a published policy")
	}
	spec.Spec.Mode = "block"
	api.call("PUT", fmt.Sprintf("/api/policies/%d", policy), spec, 200)
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		if replica.active.Load().policyBindings[site][0].Managed.Set.ID != curated.ID {
			t.Fatal("policy did not stay pinned")
		}
	}
	sealed, e := a.archiveSnapshot(a.active.Load(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	restored, e := a.decodeSnapshot(sealed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	cachedRuntime := restored.policyBindings[site][0].Managed
	defer closeManagedRuntime(cachedRuntime)
	if cachedRuntime.Set.Curation == nil || cachedRuntime.Set.ID != curated.ID || cachedRuntime.Set.Curation.SourceDigest != source.Digest {
		t.Fatal("sealed recovery cache lost curated provenance")
	}
	if !requiresRuleSimulation("PUT /api/policies/{id}") || agentScopeFor("POST /api/signature-sets") != "enforce" {
		t.Fatal("curation changed existing policy gates")
	}
}

func TestCuratedResponseSelection(t *testing.T) {
	source, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, sqlLeak)
	}))
	defer upstream.Close()
	for _, id := range []int{942100, 951120} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			set, e := curateSignatures(source, "Response selection", []int{id})
			if e != nil {
				t.Fatal(e)
			}
			options := managedSignatureOptions{SetID: set.ID, Mode: "block", ResponseMode: "block"}
			runtime, e := compileManagedSignatures(set, options)
			if e != nil {
				t.Fatal(e)
			}
			defer closeManagedRuntime(runtime)
			a := managedPublicFixture(t, upstream.URL, options)
			binding := &a.active.Load().policyBindings[1][0]
			closeManagedRuntime(binding.Managed)
			binding.Managed = runtime
			binding.ManagedOptions = runtime.Options
			r := httptest.NewRequest("GET", "http://managed.test/", nil)
			r.Header.Set("User-Agent", "browser")
			r.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()
			a.Public(w, r)
			want := 200
			if id == 951120 {
				want = 502
			}
			if w.Code != want {
				t.Fatalf("selected %d: response %d want %d", id, w.Code, want)
			}
		})
	}
}
