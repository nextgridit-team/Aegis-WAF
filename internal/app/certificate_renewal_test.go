package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestCertificateRenewalSettings(t *testing.T) {
	a, b, api, _, _ := captchaFixture(t)
	ctx := context.Background()
	var id, uploaded int64
	if err := a.db.QueryRow(ctx, `INSERT INTO certificates(name,origin,domains,not_before,not_after) VALUES('Renewal settings','acme','{renewal.test}',now()-interval '40 days',now()+interval '50 days') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(ctx, `INSERT INTO certificates(name,origin,domains) VALUES('Uploaded','upload','{upload.test}') RETURNING id`).Scan(&uploaded); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/certificates/%d/renewal", id)
	unauthenticated := testAPI{t, &http.Client{}, api.base, ""}
	unauthenticated.call("PUT", path, map[string]any{"renew_before_days": 14}, 401)
	csrf := api.csrf
	api.csrf = ""
	api.call("PUT", path, map[string]any{"renew_before_days": 14}, 403)
	api.csrf = csrf
	for _, value := range []any{0, -1, 366, 1.5, "14"} {
		api.call("PUT", path, map[string]any{"renew_before_days": value}, 400)
	}
	api.call("PUT", fmt.Sprintf("/api/certificates/%d/renewal", uploaded), map[string]any{"renew_before_days": 14}, 409)
	api.call("PUT", "/api/certificates/999999/renewal", map[string]any{"renew_before_days": 14}, 404)
	// Audit failure must roll back the setting along with the configuration version.
	if _, err := a.db.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT test_renewal_audit CHECK(action<>'certificate.renewal.updated')"); err != nil {
		t.Fatal(err)
	}
	api.call("PUT", path, map[string]any{"renew_before_days": 14}, 503)
	var days *int
	if err := b.db.QueryRow(ctx, "SELECT renew_before_days FROM certificates WHERE id=$1", id).Scan(&days); err != nil || days != nil {
		t.Fatal("failed audit persisted renewal settings", days, err)
	}
	if _, err := a.db.Exec(ctx, "ALTER TABLE audit_events DROP CONSTRAINT test_renewal_audit"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{1, 14, 45, 365, nil} {
		api.call("PUT", path, map[string]any{"renew_before_days": value}, 200)
		var records []struct {
			ID      int64      `json:"id"`
			Days    *int       `json:"renew_before_days"`
			Expires time.Time  `json:"not_after"`
			Due     *time.Time `json:"renewal_due_at"`
		}
		if err := json.Unmarshal(api.call("GET", "/api/certificates", nil, 200), &records); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range records {
			if record.ID == uploaded && record.Due != nil {
				t.Fatal("uploaded certificate has an automatic renewal date")
			}
			if record.ID != id {
				continue
			}
			found = true
			window := 30
			if value != nil {
				if record.Days == nil || *record.Days != value.(int) {
					t.Fatal("setting not returned", record)
				}
				if value.(int) < 90 {
					window = value.(int)
				}
			} else if record.Days != nil {
				t.Fatal("automatic default was not restored")
			}
			if record.Due == nil || record.Expires.Sub(*record.Due) != time.Duration(window)*24*time.Hour {
				t.Fatal("incorrect renewal start time", record)
			}
		}
		if !found {
			t.Fatal("certificate missing from inventory")
		}
	}
	var audits int
	if err := b.db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='certificate.renewal.updated'").Scan(&audits); err != nil || audits != 5 {
		t.Fatal("missing renewal audits", audits, err)
	}
	if agentScopeFor("PUT /api/certificates/{id}/renewal") != "certificates" {
		t.Fatal("incorrect agent scope")
	}
}

func TestCertificateRenewalSchedule(t *testing.T) {
	ctx := context.Background()
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	for _, tc := range []struct {
		name                string
		days                any
		lifetime, remaining int
		due                 bool
	}{
		{"default before window", nil, 90, 31, false},
		{"default due", nil, 90, 29, true},
		{"default short lifetime", nil, 21, 8, false},
		{"default short due", nil, 21, 6, true},
		{"custom later", 7, 90, 20, false},
		{"custom due", 7, 90, 6, true},
		{"custom early", 45, 90, 40, true},
		{"custom before window", 45, 90, 46, false},
		{"oversized window fresh", 365, 90, 89, false},
		{"oversized window due", 365, 90, 29, true},
		{"equal lifetime fresh", 90, 90, 89, false},
		{"expired", 1, 90, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var id int64
			if err := a.db.QueryRow(ctx, `INSERT INTO certificates(name,origin,domains,renew_before_days,not_before,not_after) VALUES($1,'acme','{renewal.test}',$2,now()+($3::int-$4::int)*interval '1 day',now()+$3::int*interval '1 day') RETURNING id`, tc.name, tc.days, tc.remaining, tc.lifetime).Scan(&id); err != nil {
				t.Fatal(err)
			}
			a.schedule(ctx)
			b.schedule(ctx)
			var jobs int
			if err := a.db.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE certificate_id=$1", id).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.due {
				want = 1
			}
			if jobs != want {
				t.Fatalf("queued %d jobs, want %d", jobs, want)
			}
		})
	}
	// Existing settings survive repeated schema initialization during replica startup.
	if err := a.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := a.db.QueryRow(ctx, "SELECT renew_before_days FROM certificates WHERE name='custom early'").Scan(&kept); err != nil || kept != 45 {
		t.Fatal("migration changed custom window", kept, err)
	}
}
