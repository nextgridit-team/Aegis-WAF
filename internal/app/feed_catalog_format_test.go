package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func communityFixture(t *testing.T) (ruleManifest, map[string][]byte) {
	t.Helper()
	raw, e := os.ReadFile("../../rules/community/release.json")
	if e != nil {
		t.Fatal(e)
	}
	base, _ := url.Parse(communityFeedURL)
	release, e := parseRuleManifest(raw, base)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile("../../rules/community/" + release.Package.Path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = parseCataloguePackage(context.Background(), release, raw); e != nil {
		t.Fatal(e)
	}
	archive, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	// Keep legacy manifest coverage independent of package directory layout.
	m := ruleManifest{SchemaVersion: 2, Name: release.Name, Revision: release.Revision, Rules: []manifestEntry{}}
	files := map[string][]byte{}
	for _, member := range archive.File {
		if !strings.HasPrefix(member.Name, "rules/") {
			continue
		}
		reader, e := member.Open()
		if e != nil {
			t.Fatal(e)
		}
		raw, e = io.ReadAll(reader)
		reader.Close()
		if e != nil {
			t.Fatal(e)
		}
		id := strings.TrimSuffix(filepath.Base(member.Name), ".json")
		sum := sha256.Sum256(raw)
		entry := manifestEntry{ID: id, Path: id + ".json", SHA256: hex.EncodeToString(sum[:])}
		m.Rules = append(m.Rules, entry)
		files[entry.Path] = raw
	}
	return m, files
}
func TestCommunityCatalogue(t *testing.T) {
	m, files := communityFixture(t)
	if len(m.Rules) < 2 || len(files) != len(m.Rules) {
		t.Fatal("expected independent PHP and Node files")
	}
}
func TestCatalogueFormatValidation(t *testing.T) {
	m, files := communityFixture(t)
	base, _ := url.Parse("https://example.com/feed/manifest.json")
	for _, path := range []string{"../rule.json", "/rule.json", "https://evil.example/rule.json", "%2e%2e/rule.json", "rules//a.json", "rule.json?token=x", "rule.json#fragment", "rules/./a.json", "rule\\x.json"} {
		if _, e := resolveRuleFile(base, path); e == nil {
			t.Fatal("unsafe rule path accepted", path)
		}
	}
	if u, e := resolveRuleFile(base, "rules/one.json"); e != nil || u != "https://example.com/feed/rules/one.json" {
		t.Fatal(u, e)
	}
	raw, _ := json.Marshal(m)
	if _, e := parseRuleManifest(append(raw, []byte(` {}`)...), base); e == nil {
		t.Fatal("accepted trailing JSON")
	}
	m.Rules = append(m.Rules, m.Rules[0])
	raw, _ = json.Marshal(m)
	if _, e := parseRuleManifest(raw, base); e == nil {
		t.Fatal("accepted duplicate entries")
	}
	m, _ = communityFixture(t)
	entry := m.Rules[0]
	raw = files[entry.Path]
	if _, e := parseCatalogueRule(append(raw, ' '), entry); e == nil {
		t.Fatal("accepted corrupted checksum")
	}
	var file feedRuleFile
	json.Unmarshal(raw, &file)
	file.Tests[0].ExpectedMatch = !file.Tests[0].ExpectedMatch
	raw, _ = json.Marshal(file)
	digest := sha256.Sum256(raw)
	entry.SHA256 = hex.EncodeToString(digest[:])
	if _, e := parseCatalogueRule(raw, entry); e == nil {
		t.Fatal("accepted failing regression vector")
	}
}
func TestCatalogueMultiFileFetch(t *testing.T) {
	m, files := communityFixture(t)
	manifest, _ := json.Marshal(m)
	count := 0
	a := &App{feedHTTP: dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		count++
		if r.Header.Get("Accept") != "application/vnd.github.raw+json" {
			t.Error("GitHub raw media type missing")
		}
		raw := manifest
		if !strings.HasSuffix(r.URL.Path, "manifest.json") {
			raw = files[filepath.Base(r.URL.Path)]
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{"fixture"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}
	_, items, tag, unchanged, e := a.fetchCatalogue(context.Background(), "https://api.github.com/repos/test/feed/contents/rules/manifest.json", "")
	if e != nil || unchanged || len(items) != len(m.Rules) || tag != "fixture" || count != len(m.Rules)+1 {
		t.Fatal("multi-file fetch failed", len(items), tag, count, e)
	}
}
