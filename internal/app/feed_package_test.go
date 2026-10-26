package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func packageFixture(t *testing.T) (ruleManifest, []byte) {
	t.Helper()
	raw, e := os.ReadFile("../../rules/community/release.json")
	if e != nil {
		t.Fatal(e)
	}
	base, _ := url.Parse(communityFeedURL)
	m, e := parseRuleManifest(raw, base)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile("../../rules/community/" + m.Package.Path)
	if e != nil {
		t.Fatal(e)
	}
	return m, raw
}
func packageDescriptor(raw []byte, count int) ruleManifest {
	sum := sha256.Sum256(raw)
	return ruleManifest{SchemaVersion: 3, Name: "Test package", Revision: 1, Package: &cataloguePackage{Path: "rules.zip", SHA256: hex.EncodeToString(sum[:]), RuleCount: count, SizeBytes: int64(len(raw))}}
}
func testArchive(t *testing.T, names []string, contents [][]byte, symlink bool) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0644)
		if symlink {
			h.SetMode(os.ModeSymlink | 0777)
		}
		f, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(contents[i]); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestCataloguePackageSafety(t *testing.T) {
	_, files := communityFixture(t)
	content := files["node-brotli-request-guard.json"]
	good := testArchive(t, []string{"rules/2026/node-brotli-request-guard.json"}, [][]byte{content}, false)
	if items, e := parseCataloguePackage(context.Background(), packageDescriptor(good, 1), good); e != nil || len(items) != 1 {
		t.Fatal(items, e)
	}
	for _, tc := range []struct {
		name     string
		names    []string
		contents [][]byte
		symlink  bool
		count    int
	}{
		{"traversal", []string{"rules/../node-brotli-request-guard.json"}, [][]byte{content}, false, 1},
		{"absolute", []string{"/rules/node-brotli-request-guard.json"}, [][]byte{content}, false, 1},
		{"duplicate names", []string{"rules/node-brotli-request-guard.json", "rules/node-brotli-request-guard.json"}, [][]byte{content, content}, false, 2},
		{"duplicate ids", []string{"rules/a/node-brotli-request-guard.json", "rules/b/node-brotli-request-guard.json"}, [][]byte{content, content}, false, 2},
		{"symlink", []string{"rules/node-brotli-request-guard.json"}, [][]byte{content}, true, 1},
		{"script", []string{"rules/run.sh"}, [][]byte{content}, false, 1},
		{"oversized", []string{"rules/node-brotli-request-guard.json"}, [][]byte{bytes.Repeat([]byte("x"), 65537)}, false, 1},
		{"wrong id", []string{"rules/other.json"}, [][]byte{content}, false, 1},
		{"wrong count", []string{"rules/node-brotli-request-guard.json"}, [][]byte{content}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := testArchive(t, tc.names, tc.contents, tc.symlink)
			if _, e := parseCataloguePackage(context.Background(), packageDescriptor(raw, tc.count), raw); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	for _, kind := range []string{"truncated", "directory count", "crc", "zip64"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte{}, good...)
			central := bytes.Index(raw, []byte{'P', 'K', 1, 2})
			switch kind {
			case "truncated":
				raw = raw[:len(raw)-1]
			case "directory count":
				binary.LittleEndian.PutUint16(raw[len(raw)-12:len(raw)-10], 2000)
			case "crc":
				raw[central+16] ^= 1
			case "zip64":
				binary.LittleEndian.PutUint32(raw[central+24:central+28], 0xffffffff)
			}
			if _, e := parseCataloguePackage(context.Background(), packageDescriptor(raw, 1), raw); e == nil {
				t.Fatal("corrupt archive accepted")
			}
		})
	}
	m := packageDescriptor(good, 1)
	m.Package.SHA256 = strings.Repeat("0", 64)
	if _, e := parseCataloguePackage(context.Background(), m, good); e == nil {
		t.Fatal("bad hash accepted")
	}
	m = packageDescriptor(good, 1)
	m.Package.SizeBytes++
	if _, e := parseCataloguePackage(context.Background(), m, good); e == nil {
		t.Fatal("bad size accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := parseCataloguePackage(ctx, packageDescriptor(good, 1), good); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestCataloguePackageFetchAndConditional(t *testing.T) {
	m, raw := packageFixture(t)
	descriptor, _ := json.Marshal(m)
	count := 0
	unchanged := false
	a := &App{feedHTTP: dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		count++
		body := raw
		status := 200
		if strings.HasSuffix(r.URL.Path, "release.json") {
			body = descriptor
			if unchanged {
				if r.Header.Get("If-None-Match") != "release7" {
					t.Error("missing conditional header")
				}
				status = 304
			}
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{"release7"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	_, items, tag, same, e := a.fetchCatalogue(context.Background(), communityFeedURL, "")
	if e != nil || same || tag != "release7" || len(items) != m.Package.RuleCount || count != 2 {
		t.Fatal(len(items), tag, count, e)
	}
	unchanged = true
	count = 0
	_, _, _, same, e = a.fetchCatalogue(context.Background(), communityFeedURL, "release7")
	if e != nil || !same || count != 1 {
		t.Fatal(count, same, e)
	}
	base, _ := url.Parse(communityFeedURL)
	for _, change := range []func(*ruleManifest){
		func(m *ruleManifest) { m.Package.Path = "../rules.zip" },
		func(m *ruleManifest) { m.Package.SizeBytes = maxCataloguePackageBytes + 1 },
		func(m *ruleManifest) { m.Package.RuleCount = 2001 },
		func(m *ruleManifest) { m.Package.SHA256 = "bad" },
		func(m *ruleManifest) { m.Rules = []manifestEntry{} },
	} {
		bad, _ := packageFixture(t)
		change(&bad)
		b, _ := json.Marshal(bad)
		if _, e := parseRuleManifest(b, base); e == nil {
			t.Fatal("bad descriptor accepted", string(b))
		}
	}
	if _, e := parseRuleManifest(append(descriptor, bytes.Repeat([]byte(" "), 4096)...), base); e == nil {
		t.Fatal("large descriptor accepted")
	}
}
func TestCataloguePackageIntegration(t *testing.T) {
	a, b, api, _, _ := captchaFixture(t)
	ctx := context.Background()
	m, raw := packageFixture(t)
	descriptor, _ := json.Marshal(m)
	count := 0
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		count++
		body := raw
		if strings.HasSuffix(r.URL.Path, "release.json") {
			body = descriptor
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	id := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Packaged catalogue", "url": "https://example.com/release.json"}, 201))
	path := fmt.Sprintf("/api/rule-feeds/%d/sync", id)
	api.call("POST", path, map[string]any{}, 200)
	var before, after int
	a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1", id).Scan(&before)
	if before != m.Package.RuleCount || count != 2 {
		t.Fatal(before, count)
	}
	// Invalid updates report failure and retain every last-good entry.
	raw[0] ^= 1
	api.call("POST", path, map[string]any{}, 400)
	a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1", id).Scan(&after)
	var failure string
	a.db.QueryRow(ctx, "SELECT error FROM rule_feeds WHERE id=$1", id).Scan(&failure)
	if before != after || failure == "" {
		t.Fatal("last-good catalogue/error not retained", before, after, failure)
	}
	// Only the exact official URL changes; policy snapshots remain byte-identical.
	var official int64
	var pinnedBefore, pinnedAfter string
	a.db.QueryRow(ctx, "SELECT id FROM rule_feeds WHERE url=$1", communityFeedURL).Scan(&official)
	a.db.QueryRow(ctx, "SELECT md5(string_agg(spec::text,',' ORDER BY id)) FROM policies").Scan(&pinnedBefore)
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET url=$2,name='My official source' WHERE id=$1", official, legacyCommunityFeedURL); e != nil {
		t.Fatal(e)
	}
	if e := b.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	var name, u string
	a.db.QueryRow(ctx, "SELECT name,url FROM rule_feeds WHERE id=$1", official).Scan(&name, &u)
	a.db.QueryRow(ctx, "SELECT md5(string_agg(spec::text,',' ORDER BY id)) FROM policies").Scan(&pinnedAfter)
	if name != "My official source" || u != communityFeedURL || pinnedBefore != pinnedAfter {
		t.Fatal("source migration changed identity or pinned policy", name, u)
	}
	a.db.QueryRow(ctx, "SELECT url FROM rule_feeds WHERE id=$1", id).Scan(&u)
	if u != "https://example.com/release.json" {
		t.Fatal("custom source changed", u)
	}
}
