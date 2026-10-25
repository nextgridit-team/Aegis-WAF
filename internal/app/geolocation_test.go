package app

import (
	"github.com/oschwald/maxminddb-golang/v2"
	"net/netip"
	"os"
	"testing"
)

// Optional vendor download fixture; never includes visitor data or a database in the image.
func TestDownloadedCountryDatabase(t *testing.T) {
	file := os.Getenv("TEST_COUNTRY_DATABASE_FILE")
	if file == "" {
		t.Skip("set TEST_COUNTRY_DATABASE_FILE to validate a downloaded MMDB")
	}
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	db, e := maxminddb.OpenBytes(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.Verify(); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if country := countryFor(db, netip.MustParseAddr(ip)); len(country) != 2 {
			t.Fatalf("no country for %s", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "::1", "fc00::1"} {
		if countryFor(db, netip.MustParseAddr(ip)) != "" {
			t.Fatal("private IP acquired location")
		}
	}
	if _, e = maxminddb.OpenBytes([]byte("invalid database")); e == nil {
		t.Fatal("corrupt database accepted")
	}
}
