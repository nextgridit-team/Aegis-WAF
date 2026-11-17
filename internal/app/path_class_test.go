package app

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizePathClass(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"static path", "/api/items", "/api/items"},
		{"root", "/", "/"},
		{"empty", "", "/"},
		{"numeric segment", "/api/items/123", "/api/items/{id}"},
		{"multiple numeric", "/api/items/123/reviews/456", "/api/items/{id}/reviews/{id}"},
		{"uuid", "/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{uuid}"},
		{"uuid uppercase", "/api/users/550E8400-E29B-41D4-A716-446655440000", "/api/users/{uuid}"},
		{"query string excluded", "/api/items?page=2&sort=desc", "/api/items"},
		{"fragment excluded", "/api/items#top", "/api/items"},
		{"long hex hash", "/files/90f3b12c45d67890a1b2c3d4e5f60718", "/files/{hash}"},
		{"short hex stays", "/words/deadbeef", "/words/deadbeef"},
		{"versioned path stays", "/api/v1/items", "/api/v1/items"},
		{"numeric prefix of uuid-shaped hex", "/digits/0000000000000000", "/digits/{id}"},
		{"leading digits with letters stay", "/release/v2a", "/release/v2a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePathClass(tc.in); got != tc.want {
				t.Fatalf("normalizePathClass(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizePathClassBoundedLength(t *testing.T) {
	long := "/" + strings.Repeat("a", 300)
	if got := normalizePathClass(long); len(got) > pathClassMaxBytes {
		t.Fatalf("class length %d exceeds bound %d", len(got), pathClassMaxBytes)
	}
}

func TestNormalizePathClassValidUTF8(t *testing.T) {
	// net/http percent-decodes /%ff%fe into raw invalid bytes in r.URL.Path;
	// one invalid path class would fail the whole access-log CopyFrom batch
	// (SQLSTATE 22021), dropping every event in the batch.
	cases := []string{
		"/api/items/\xff\xfe",
		"/\xff",
		"/api/" + strings.Repeat("\xc3", 70), // dangling multibyte prefix, over segment bound
		"/" + strings.Repeat("a", 70) + "\xff" + strings.Repeat("b", 70), // invalid inside over-bound segment
	}
	for _, in := range cases {
		got := normalizePathClass(in)
		if !utf8.ValidString(got) {
			t.Fatalf("normalizePathClass(%q) = %q is not valid UTF-8", in, got)
		}
		// Byte 0xff never appears in valid UTF-8, so this cannot confuse the
		// U+FFFD replacement rune (which IS valid UTF-8) with raw garbage.
		if strings.IndexByte(got, 0xff) >= 0 || strings.IndexByte(got, 0xfe) >= 0 {
			t.Fatalf("normalizePathClass(%q) = %q still carries raw invalid bytes", in, got)
		}
	}
	// A long multibyte segment truncated at the byte bound must not slice
	// mid-rune: the truncation is rune-safe even after sanitization.
	cjk := "/" + strings.Repeat("世", 40)
	if got := normalizePathClass(cjk); !utf8.ValidString(got) {
		t.Fatalf("multibyte truncation produced invalid UTF-8: %q", got)
	}
}

func TestPathClassTrackerBoundedCardinality(t *testing.T) {
	tracker := &pathClassTracker{}
	site := int64(7)
	if got := tracker.classify(site, "/api/items/42"); got != "/api/items/{id}" {
		t.Fatalf("first class = %q", got)
	}
	// Fill the per-site budget with distinct static classes; the first class
	// already occupies one slot.
	for i := 0; i < pathClassCapPerSite-1; i++ {
		if got := tracker.classify(site, fmt.Sprintf("/class-x%d", i)); got == pathClassOverflow {
			t.Fatalf("class %d folded into overflow before the cap", i)
		}
	}
	// The next distinct class must fold into the overflow bucket.
	if got := tracker.classify(site, "/brand/new"); got != pathClassOverflow {
		t.Fatalf("distinct class past the cap = %q, want %q", got, pathClassOverflow)
	}
	// Repeated overflow stays stable and existing classes keep resolving.
	if got := tracker.classify(site, "/another/new"); got != pathClassOverflow {
		t.Fatalf("second overflow class = %q", got)
	}
	if got := tracker.classify(site, "/api/items/43"); got != "/api/items/{id}" {
		t.Fatalf("existing class no longer resolves: %q", got)
	}
	// The map itself stays bounded: exactly the cap plus the overflow bucket.
	tracker.mu.Lock()
	size := len(tracker.sites[site])
	tracker.mu.Unlock()
	if size != pathClassCapPerSite {
		t.Fatalf("tracked classes = %d, want %d", size, pathClassCapPerSite)
	}
	// Another application gets its own budget.
	if got := tracker.classify(8, "/brand/new"); got != "/brand/new" {
		t.Fatalf("second site class = %q", got)
	}
}

func TestPathClassTrackerBoundedSites(t *testing.T) {
	tracker := &pathClassTracker{}
	for i := 0; i < pathClassMaxSites; i++ {
		tracker.classify(int64(i), "/api/items/1")
	}
	if got := tracker.classify(int64(pathClassMaxSites), "/api/items/1"); got != pathClassOverflow {
		t.Fatalf("class beyond the site bound = %q, want %q", got, pathClassOverflow)
	}
	tracker.mu.Lock()
	sites := len(tracker.sites)
	tracker.mu.Unlock()
	if sites != pathClassMaxSites {
		t.Fatalf("tracked sites = %d, want %d", sites, pathClassMaxSites)
	}
}
