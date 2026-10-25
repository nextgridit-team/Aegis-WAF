package app

import (
	"strings"
	"testing"
)

func TestSignatureInventory(t *testing.T) {
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	entries, e := inventoryForSignatures(set)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != set.RuleCount {
		t.Fatalf("inventory %d entries, corpus %d", len(entries), set.RuleCount)
	}
	sql, response, setup := false, false, false
	for _, entry := range entries {
		if entry.ID == 942100 {
			sql = true
			if !strings.Contains(strings.ToLower(entry.Name), "sql") || entry.Scope != "request" || entry.Paranoia != 1 {
				t.Fatalf("SQL rule metadata: %+v", entry)
			}
		}
		response = response || entry.Scope == "response"
		setup = setup || entry.Scope == "setup"
	}
	if !sql || !response || !setup {
		t.Fatal("inventory scope incomplete")
	}
	again, e := inventoryForSignatures(set)
	if e != nil || len(again) != len(entries) {
		t.Fatal("immutable inventory cache", e)
	}
}
