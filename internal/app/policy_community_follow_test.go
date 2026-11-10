package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	community "github.com/nextgridit-team/Aegis-WAF/rules/community"
)

type followRelease struct {
	manifest, archive []byte
	etag              string
}

func followFixture(t *testing.T, revision int, files map[string][]byte) *followRelease {
	t.Helper()
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	paths, contents := []string{}, [][]byte{}
	for _, name := range names {
		paths = append(paths, "rules/"+name)
		contents = append(contents, files[name])
	}
	archive := testArchive(t, paths, contents, false)
	manifest := packageDescriptor(archive, len(files))
	manifest.Revision = revision
	raw, _ := json.Marshal(manifest)
	return &followRelease{raw, archive, fmt.Sprintf("release-%d", revision)}
}

func readFollowingPolicy(t *testing.T, a *App, id int64) (policySpec, int64) {
	t.Helper()
	var raw []byte
	var revision int64
	var spec policySpec
	if e := a.db.QueryRow(context.Background(), "SELECT spec,revision FROM policies WHERE id=$1", id).Scan(&raw, &revision); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &spec); e != nil {
		t.Fatal(e)
	}
	return spec, revision
}

func TestCommunityScheduledFollowEnforcement(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	manifest, all := communityFixture(t)
	legacyRaw, _ := community.Files.ReadFile("manifest.json")
	var legacy ruleManifest
	if e := json.Unmarshal(legacyRaw, &legacy); e != nil {
		t.Fatal(e)
	}
	old := map[string][]byte{}
	for _, item := range legacy.Rules {
		old[item.ID+".json"] = all[item.ID+".json"]
	}
	var release atomic.Pointer[followRelease]
	release.Store(followFixture(t, manifest.Revision+1, old))
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		current := release.Load()
		raw := current.manifest
		if strings.HasSuffix(r.URL.Path, ".zip") {
			raw = current.archive
		}
		status := 200
		if r.Header.Get("If-None-Match") == current.etag && !strings.HasSuffix(r.URL.Path, ".zip") {
			status = 304
			raw = nil
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{current.etag}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	var feedID int64
	if e := a.db.QueryRow(ctx, "SELECT feed_id FROM built_in_rule_feeds WHERE key='aegis-community'").Scan(&feedID); e != nil {
		t.Fatal(e)
	}
	if e := a.syncFeed(ctx, feedID, true, "test-setup"); e != nil {
		t.Fatal(e)
	}
	var upstream string
	if e := a.db.QueryRow(ctx, "SELECT upstream FROM sites WHERE id=$1", site).Scan(&upstream); e != nil {
		t.Fatal(e)
	}
	var selected []int64
	rows, e := a.db.Query(ctx, "SELECT id FROM rule_catalog WHERE feed_id=$1 AND available ORDER BY id", feedID)
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			t.Fatal(e)
		}
		selected = append(selected, id)
	}
	rows.Close()
	type target struct {
		name, mode, update, communityMode string
		enabled                           bool
		id, revision                      int64
	}
	targets := []target{
		{name: "block", mode: "block", update: "follow", enabled: true},
		{name: "observe", mode: "observe", update: "follow", enabled: true},
		{name: "off", mode: "off", update: "follow", enabled: true},
		{name: "community-observe", mode: "block", communityMode: "observe", update: "follow", enabled: true},
		{name: "disabled", mode: "block", update: "follow", enabled: false},
		{name: "pinned", mode: "block", update: "pinned", enabled: true},
	}
	for i := range targets {
		target := &targets[i]
		appID := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": target.name, "hostnames": []string{target.name + ".test"}, "upstream": upstream, "enabled": true, "redirect_https": false}, 200))
		input := policyInput{Spec: policySpecInput{Name: target.name, Mode: target.mode, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{}, Community: &policyCommunityInput{Enabled: target.enabled, Mode: target.communityMode, UpdateMode: target.update, RuleIDs: selected}}, Applications: []policyAssignment{{SiteID: appID, SourceCIDRs: []string{}}}}
		target.id = mustID(t, api.call("POST", "/api/policies", input, 200))
		target.revision = 1
	}
	probe := func(replica *App, host, path string, headers map[string]string) int {
		r := httptest.NewRequest("GET", "http://"+host+".test"+path, nil)
		r.Header.Set("User-Agent", "browser")
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		replica.Public(w, r)
		return w.Code
	}
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		if got := probe(replica, "block", "/wp-content/upgrade/", nil); got != 200 {
			t.Fatal("pre-release control", got)
		}
	}
	// Update an existing rule, withdraw one, and add the five real guards together.
	var revised feedRuleFile
	if e := json.Unmarshal(all["node-brotli-request-guard.json"], &revised); e != nil {
		t.Fatal(e)
	}
	revised.Revision++
	revised.Description += " Fixture revision."
	all["node-brotli-request-guard.json"], _ = json.Marshal(revised)
	delete(all, "kev-gitlab-file-path-traversal.json")
	release.Store(followFixture(t, manifest.Revision+2, all))
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET next_sync=now() WHERE id=$1", feedID); e != nil {
		t.Fatal(e)
	}
	// Only the real scheduler and snapshot refresh run after publication: no sync,
	// save, refresh-rule or activation API calls are involved in this transition.
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{}, 3)
	go func() { defer func() { done <- struct{}{} }(); a.FeedWorker(workerCtx) }()
	go func() { defer func() { done <- struct{}{} }(); a.Background(workerCtx) }()
	go func() { defer func() { done <- struct{}{} }(); b.Background(workerCtx) }()
	t.Cleanup(func() {
		cancel()
		for i := 0; i < 3; i++ {
			<-done
		}
	})
	deadline := time.Now().Add(45 * time.Second)
	for {
		if probe(a, "block", "/wp-content/upgrade/", nil) == 403 && probe(b, "block", "/wp-content/upgrade/", nil) == 403 {
			break
		}
		if time.Now().After(deadline) {
			var failure string
			a.db.QueryRow(ctx, "SELECT error FROM rule_feeds WHERE id=$1", feedID).Scan(&failure)
			t.Fatal("scheduled enforcement not reached", failure)
		}
		time.Sleep(time.Second)
	}
	for _, target := range targets {
		want := 200
		if target.name == "block" {
			want = 403
		}
		for _, replica := range []*App{a, b} {
			for _, path := range []string{"/wp-content/upgrade/", "/wp-content/uploads/wpcf7_uploads/123/file.phar", "/api/v4/projects/group%2Fproject/ci/lint", "/group/project/-/blob/main/file.org"} {
				if got := probe(replica, target.name, path, nil); got != want {
					t.Fatalf("%s %s: got %d want %d", target.name, path, got, want)
				}
			}
			if got := probe(replica, target.name, "/v2/users", map[string]string{"X-GPUStack-Real-IP": "127.0.0.1"}); got != want {
				t.Fatalf("%s GPUStack: %d", target.name, got)
			}
			if got := probe(replica, target.name, "/health", nil); got != 200 {
				t.Fatal("benign control blocked", got)
			}
		}
		spec, revision := readFollowingPolicy(t, a, target.id)
		adopted := target.update == "follow" && target.enabled
		wantCount := len(old)
		if adopted {
			wantCount = len(all)
		}
		if len(spec.Community.Rules) != wantCount || spec.Mode != target.mode || spec.Community.Enabled != target.enabled {
			t.Fatal("selection/mode changed incorrectly", target.name)
		}
		if adopted && revision != 2 || !adopted && revision != 1 {
			t.Fatal("unexpected policy revision", target.name, revision)
		}
		for _, rule := range spec.Community.Rules {
			if adopted && rule.Feed.EntryID == "node-brotli-request-guard" && rule.Feed.Revision != revised.Revision {
				t.Fatal("existing rule revision not adopted")
			}
			if adopted && rule.Feed.EntryID == "kev-gitlab-file-path-traversal" {
				t.Fatal("withdrawn rule still enabled")
			}
		}
	}
	var auditCount int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='policy.feed_updated'").Scan(&auditCount); e != nil {
		t.Fatal(e)
	}
	if auditCount < 4 {
		t.Fatal("missing automatic policy audit records", auditCount)
	}
	// The ETag/304 path is idempotent, and rollback freezes the chosen history.
	if e := a.syncFeed(ctx, feedID, true, "test"); e != nil {
		t.Fatal(e)
	}
	_, rev := readFollowingPolicy(t, a, targets[0].id)
	if rev != 2 {
		t.Fatal("304 duplicated history", rev)
	}
	api.call("POST", fmt.Sprintf("/api/policies/%d/rollback", targets[0].id), map[string]int64{"revision": rev, "target_revision": 1}, 200)
	if e := a.syncFeed(ctx, feedID, true, "test"); e != nil {
		t.Fatal(e)
	}
	rolled, _ := readFollowingPolicy(t, a, targets[0].id)
	if rolled.Community.UpdateMode != "pinned" || len(rolled.Community.Rules) != len(old) {
		t.Fatal("rollback was not pinned")
	}
	// A release that cannot fit a policy is rejected as one transaction.
	for n := 0; n < 2; n++ {
		clone := revised
		clone.ID = fmt.Sprintf("capacity-new-%d", n)
		clone.Revision = 1
		all[clone.ID+".json"], _ = json.Marshal(clone)
	}
	release.Store(followFixture(t, manifest.Revision+3, all))
	if e := a.syncFeed(ctx, feedID, true, "test"); e == nil {
		t.Fatal("oversized automatic policy accepted")
	}
	var stored int
	var failure string
	if e := a.db.QueryRow(ctx, "SELECT manifest_revision,error FROM rule_feeds WHERE id=$1", feedID).Scan(&stored, &failure); e != nil {
		t.Fatal(e)
	}
	if stored != manifest.Revision+2 || failure == "" {
		t.Fatal("failed release damaged last-good catalogue or hid failure", stored, failure)
	}
	_, rev = readFollowingPolicy(t, a, targets[1].id)
	if rev != 2 {
		t.Fatal("failed release changed policy history", rev)
	}
	api.call("DELETE", fmt.Sprintf("/api/rule-feeds/%d", feedID), nil, 200)
	for _, target := range targets {
		spec, _ := readFollowingPolicy(t, a, target.id)
		if spec.Community.UpdateMode != "pinned" || spec.Community.Enabled != target.enabled {
			t.Fatal("source removal did not pin existing selection", target.name)
		}
	}
	restored := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Restored official feed", "url": communityFeedURL}, 201))
	var linked int64
	if e := a.db.QueryRow(ctx, "SELECT feed_id FROM built_in_rule_feeds WHERE key='aegis-community'").Scan(&linked); e != nil || linked != restored {
		t.Fatal("restored official source cannot be followed", linked, e)
	}
}

func TestCommunityFollowMigration(t *testing.T) {
	a, _, _, _, _ := captchaFixture(t)
	ctx := context.Background()
	var baseline int64
	if e := a.db.QueryRow(ctx, "SELECT policy_id FROM built_in_policies WHERE key='baseline-protection'").Scan(&baseline); e != nil {
		t.Fatal(e)
	}
	spec, _ := readFollowingPolicy(t, a, baseline)
	legacyRaw, _ := community.Files.ReadFile("manifest.json")
	var legacy ruleManifest
	json.Unmarshal(legacyRaw, &legacy)
	wanted := map[string]bool{}
	for _, r := range legacy.Rules {
		wanted[r.ID] = true
	}
	old := []policyRule{}
	for _, r := range spec.Community.Rules {
		if wanted[r.Feed.EntryID] {
			old = append(old, r)
		}
	}
	for _, tc := range []struct {
		name             string
		rules            []policyRule
		disabled, scoped bool
		want             string
	}{
		{"old full feed after download", old, false, false, "follow"},
		{"disabled full feed", old, true, false, "follow"},
		{"custom subset", old[:1], false, false, "pinned"},
		{"scoped full selection", old, false, true, "pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := spec
			c := *spec.Community
			s.Community = &c
			c.UpdateMode = ""
			c.Rules = tc.rules
			c.Enabled = !tc.disabled
			s.Mode = "observe"
			if tc.scoped {
				s.Groups = []policyGroup{{Name: "Scoped", PathPrefix: "/private", Rules: old}}
			}
			raw, _ := json.Marshal(s)
			var id int64
			if e := a.db.QueryRow(ctx, "INSERT INTO policies(spec) VALUES($1) RETURNING id", raw).Scan(&id); e != nil {
				t.Fatal(e)
			}
			if e := a.change(ctx, func(tx pgx.Tx) error { return upgradeCommunityFollowing(ctx, tx) }); e != nil {
				t.Fatal(e)
			}
			got, rev := readFollowingPolicy(t, a, id)
			if got.Community.UpdateMode != tc.want || got.Community.Enabled == tc.disabled || got.Mode != "observe" || rev != 2 {
				t.Fatal("incorrect migration", got.Community.UpdateMode, rev)
			}
			if e := a.initialize(ctx); e != nil {
				t.Fatal(e)
			}
			_, again := readFollowingPolicy(t, a, id)
			if again != rev {
				t.Fatal("migration repeated")
			}
		})
	}
}
