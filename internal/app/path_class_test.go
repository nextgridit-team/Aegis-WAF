package app

import (
	"fmt"
	"strings"
	"testing"
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
