package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEvidenceGlobalWindowBeforeCleanup(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	// Keep an old sample physically present, with a future per-site expiry.
	// Reads must enforce the shorter global window without relying on cleanup.
	for _, sample := range []struct {
		id  string
		age int
	}{{"outside-global", 7}, {"inside-global", 1}} {
		data := `{"schema_version":1,"facts":{"path:":{"state":"present","values":["/private-marker"]}}}`
		if _, err := a.db.Exec(ctx, "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) VALUES($1,now()-make_interval(hours=>$2),$3,now()+interval '1 day',$4)", sample.id, sample.age, site, data); err != nil {
			t.Fatal(err)
		}
	}
	var id int64
	if err := a.db.QueryRow(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,event_id) VALUES(now(),$1,'GET',200,1,'192.0.2.1','outside-global') RETURNING id", site).Scan(&id); err != nil {
		t.Fatal(err)
	}
	detail := api.call("GET", fmt.Sprintf("/api/access-logs/%d", id), nil, 200)
	if strings.Contains(string(detail), "private-marker") || !strings.Contains(string(detail), `"evidence_state":"expired"`) {
		t.Fatal("global expiry not enforced on detail", string(detail))
	}
	var events []struct {
		ID      string    `json:"id"`
		Expires time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(api.call("GET", "/api/traffic-events", nil, 200), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "inside-global" || events[0].Expires.After(time.Now().Add(5*time.Hour+time.Minute)) {
		t.Fatal("evidence list ignored effective expiry", events)
	}
	rule := probeRule("path", "", "prefix", "/private")
	rule.Scope.SiteID = site
	api.call("POST", "/api/rules/replay", map[string]any{"rule": rule, "event_ids": []string{"outside-global"}}, 400)
	api.call("POST", "/api/rules/replay", map[string]any{"rule": rule, "event_ids": []string{"inside-global"}}, 200)
	rule.EvidenceIDs = []string{"outside-global"}
	api.call("POST", "/api/rules", rule, 400)
	var count int
	if err := a.db.QueryRow(ctx, "SELECT count(*) FROM traffic_evidence WHERE id='outside-global'").Scan(&count); err != nil || count != 1 {
		t.Fatal("test unexpectedly depended on physical deletion", count, err)
	}
}
