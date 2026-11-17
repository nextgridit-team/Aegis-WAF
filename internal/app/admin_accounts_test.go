package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The TOTP codes used by these tests are computed by an independent
// implementation of RFC 6238 rather than the production one, so a shared bug
// cannot satisfy both sides. TestAdminTOTPHelperRFCVectors pins this helper
// against the RFC 6238 Appendix B reference values (truncated to six digits).
func adminTestTOTP(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]) & 0x7f) << 24
	value |= uint32(sum[offset+1]) << 16
	value |= uint32(sum[offset+2]) << 8
	value |= uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}

func adminTestDecodeSecret(t *testing.T, secret string) []byte {
	t.Helper()
	raw, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		t.Fatalf("enrollment secret is not valid base32: %v", e)
	}
	return raw
}

func TestAdminTOTPHelperRFCVectors(t *testing.T) {
	secret := adminTestDecodeSecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range vectors {
		if got := adminTestTOTP(secret, v.unix/30); got != v.code {
			t.Fatalf("helper TOTP(unix=%d) = %s, want %s", v.unix, got, v.code)
		}
	}
}

func adminFixture(t *testing.T) (Config, *App, *httptest.Server) {
	t.Helper()
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	s := httptest.NewServer(a.Management())
	t.Cleanup(s.Close)
	return cfg, a, s
}

func adminClient(t *testing.T, server *httptest.Server) testAPI {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	// A generous budget: recovery-code hashing and comparison are bcrypt-bound
	// and slow further under -race on a loaded host.
	client := &http.Client{Jar: jar, Timeout: 60 * time.Second}
	return testAPI{t, client, server.URL, ""}
}

func adminLogin(t *testing.T, c testAPI, username, password string) map[string]any {
	t.Helper()
	var out map[string]any
	data := c.call("POST", "/api/login", map[string]string{"username": username, "password": password}, 200)
	if e := json.Unmarshal(data, &out); e != nil {
		t.Fatalf("login response is not JSON: %s", data)
	}
	return out
}

func adminAuditCount(t *testing.T, a *App, action string) int {
	t.Helper()
	var n int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE action=$1", action).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

func adminTestPolicy(name string) policyInput {
	return policyInput{Spec: policySpecInput{Name: name, Mode: "observe", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{}}, Applications: []policyAssignment{}}
}

const (
	adminOwnerPW    = "owner workspace password"
	adminViewerPW   = "viewer workspace password"
	adminOperatorPW = "operator workspace password"
)

// The role matrix: read-only is denied every mutation, operators run the
// workspace but cannot manage administrators or credential minting, and only
// owners manage accounts. On main there are no roles and every administrator
// holds the whole surface — the read-only POST /api/policies below succeeds
// there, which is exactly the gap issue #52 describes.
func TestAdministratorRoleMatrix(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = cfg
	owner := adminClient(t, s)
	owner.call("POST", "/api/setup", map[string]string{"username": "owner-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	ownerLogin := adminLogin(t, owner, "owner-admin", adminOwnerPW)
	owner.csrf = ownerLogin["csrf"].(string)

	// Only owners see and manage administrators.
	owner.call("POST", "/api/administrators", map[string]string{"username": "viewer", "password": adminViewerPW, "role": "read_only"}, 201)
	owner.call("POST", "/api/administrators", map[string]string{"username": "operator", "password": adminOperatorPW, "role": "operator"}, 201)
	owner.call("POST", "/api/administrators", map[string]string{"username": "bad-role", "password": adminOperatorPW, "role": "supervisor"}, 400)
	var admins []map[string]any
	if e := json.Unmarshal(owner.call("GET", "/api/administrators", nil, 200), &admins); e != nil {
		t.Fatal(e)
	}
	if len(admins) != 3 {
		t.Fatalf("want three administrators, got %d", len(admins))
	}
	ids := map[string]int64{}
	for _, row := range admins {
		ids[row["username"].(string)] = int64(row["id"].(float64))
		if row["username"] == "owner-admin" && row["role"] != "owner" {
			t.Fatalf("bootstrapped administrator role = %v, want owner", row["role"])
		}
	}

	viewer := adminClient(t, s)
	viewer.csrf = adminLogin(t, viewer, "viewer", adminViewerPW)["csrf"].(string)
	operator := adminClient(t, s)
	operator.csrf = adminLogin(t, operator, "operator", adminOperatorPW)["csrf"].(string)

	// Read-only keeps read access everywhere it is granted at all.
	viewer.call("GET", "/api/policies", nil, 200)
	viewer.call("GET", "/api/sites", nil, 200)
	viewer.call("GET", "/api/status", nil, 200)

	// Read-only is denied every mutation, including the acceptance red.
	if body := string(viewer.call("POST", "/api/policies", adminTestPolicy("Viewer denied"), 403)); !strings.Contains(body, "role") {
		t.Fatalf("denial must name the role requirement: %s", body)
	}
	viewer.call("POST", "/api/sites", map[string]any{}, 403)
	viewer.call("PUT", "/api/log-settings", map[string]any{}, 403)
	viewer.call("DELETE", "/api/policies/999", nil, 403)

	// Credential minting and administrator management are owner-only.
	viewer.call("GET", "/api/agent-keys", nil, 403)
	viewer.call("POST", "/api/agent-keys", map[string]any{}, 403)
	operator.call("GET", "/api/agent-keys", nil, 403)
	operator.call("POST", "/api/agent-keys", map[string]any{}, 403)
	operator.call("GET", "/api/administrators", nil, 403)
	operator.call("POST", "/api/administrators", map[string]string{"username": "sneaky", "password": adminOperatorPW, "role": "owner"}, 403)
	operator.call("PUT", fmt.Sprintf("/api/administrators/%d/role", ids["viewer"]), map[string]string{"role": "owner"}, 403)

	// Operators run the workspace.
	mustID(t, operator.call("POST", "/api/policies", adminTestPolicy("Operator policy"), 200))
	operator.call("PUT", "/api/log-settings", map[string]any{"retention_hours": 6, "audit_retention_hours": 720, "revision": 1}, 200)

	// Self-service account routes stay available to every role.
	viewer.call("POST", "/api/password", map[string]string{"current_password": adminViewerPW, "new_password": adminViewerPW + "2"}, 200)

	// Role changes are audited and cannot target yourself.
	if n := adminAuditCount(t, a, "administrator.role_changed"); n != 0 {
		t.Fatalf("role_changed audit before any change: %d", n)
	}
	owner.call("PUT", fmt.Sprintf("/api/administrators/%d/role", ids["operator"]), map[string]string{"role": "read_only"}, 200)
	owner.call("PUT", fmt.Sprintf("/api/administrators/%d/role", ids["owner-admin"]), map[string]string{"role": "operator"}, 400)
	owner.call("PUT", fmt.Sprintf("/api/administrators/%d/role", ids["operator"]), map[string]string{"role": "not-a-role"}, 400)
	if n := adminAuditCount(t, a, "administrator.role_changed"); n != 1 {
		t.Fatalf("role_changed audit rows = %d, want 1", n)
	}

	// /api/me reports the current role and MFA state.
	var me map[string]any
	if e := json.Unmarshal(owner.call("GET", "/api/me", nil, 200), &me); e != nil {
		t.Fatal(e)
	}
	if me["role"] != "owner" || me["mfa_enabled"] != false {
		t.Fatalf("/api/me = %v, want role owner and mfa_enabled false", me)
	}
}

// TOTP enrollment, enforcement at login, ticket single-use, replay rejection
// and one-time recovery codes. On main there is no MFA: password login
// immediately mints a session for an enrolled administrator.
func TestAdministratorMFAEnrollmentAndLogin(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = a
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "mfa-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "mfa-admin", adminOwnerPW)["csrf"].(string)

	var enroll map[string]string
	if e := json.Unmarshal(c.call("POST", "/api/mfa/enroll", map[string]any{}, 200), &enroll); e != nil {
		t.Fatal(e)
	}
	if len(enroll["secret"]) < 26 || !strings.Contains(enroll["uri"], "otpauth://totp/") || !strings.Contains(enroll["uri"], enroll["secret"]) {
		t.Fatalf("enrollment response must carry the secret and otpauth URI: %v", enroll)
	}
	secret := adminTestDecodeSecret(t, enroll["secret"])

	// A wrong confirmation code is rejected.
	c.call("POST", "/api/mfa/confirm", map[string]string{"code": "000000"}, 400)

	// Confirming activates MFA and returns recovery codes exactly once.
	code := adminTestTOTP(secret, time.Now().Unix()/30)
	var confirmed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if e := json.Unmarshal(c.call("POST", "/api/mfa/confirm", map[string]string{"code": code}, 200), &confirmed); e != nil {
		t.Fatal(e)
	}
	if len(confirmed.RecoveryCodes) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(confirmed.RecoveryCodes))
	}
	seen := map[string]bool{}
	for _, rc := range confirmed.RecoveryCodes {
		if len(rc) != 16 || seen[rc] {
			t.Fatalf("recovery codes must be 16 characters and distinct: %q", rc)
		}
		seen[rc] = true
	}
	if n := adminAuditCount(t, a, "administrator.mfa_enrolled"); n != 1 {
		t.Fatalf("mfa_enrolled audit rows = %d, want 1", n)
	}

	// Enabling MFA revokes every session, including the enrolling one.
	c.call("GET", "/api/me", nil, 401)

	// Password login withholds the session and demands the second factor.
	c2 := adminClient(t, s)
	pending := adminLogin(t, c2, "mfa-admin", adminOwnerPW)
	if pending["mfa_required"] != true || pending["ticket"] == "" || pending["csrf"] != nil {
		t.Fatalf("password login for an enrolled administrator must return mfa_required and a ticket: %v", pending)
	}
	c2.call("GET", "/api/me", nil, 401)
	ticket := pending["ticket"].(string)

	// Wrong codes are rejected without burning the ticket.
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": ticket, "code": "000000"}, 401)

	// The correct code completes login.
	fresh := adminTestTOTP(secret, time.Now().Unix()/30)
	var login map[string]any
	if e := json.Unmarshal(c2.call("POST", "/api/login/mfa", map[string]string{"ticket": ticket, "code": fresh}, 200), &login); e != nil {
		t.Fatal(e)
	}
	if login["csrf"] == "" || login["username"] != "mfa-admin" {
		t.Fatalf("second-factor login response: %v", login)
	}
	c2.csrf = login["csrf"].(string)
	c2.call("GET", "/api/policies", nil, 200)

	// The ticket is single-use.
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": ticket, "code": fresh}, 401)

	// A replayed code is refused; the next recovery code works.
	c2.call("POST", "/api/logout", nil, 200)
	pending = adminLogin(t, c2, "mfa-admin", adminOwnerPW)
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": pending["ticket"].(string), "code": fresh}, 401)
	var viaRecovery map[string]any
	if e := json.Unmarshal(c2.call("POST", "/api/login/mfa", map[string]string{"ticket": pending["ticket"].(string), "code": confirmed.RecoveryCodes[0]}, 200), &viaRecovery); e != nil {
		t.Fatal(e)
	}
	c2.csrf = viaRecovery["csrf"].(string)
	c2.call("GET", "/api/me", nil, 200)

	// Recovery codes are single-use.
	c2.call("POST", "/api/logout", nil, 200)
	pending = adminLogin(t, c2, "mfa-admin", adminOwnerPW)
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": pending["ticket"].(string), "code": confirmed.RecoveryCodes[0]}, 401)
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": pending["ticket"].(string), "code": confirmed.RecoveryCodes[1]}, 200)

	// The secret and recovery codes are never returned by any read.
	for _, body := range [][]byte{
		c2.call("GET", "/api/me", nil, 200),
		c2.call("GET", "/api/sessions", nil, 200),
		ownerCallAdministrators(t, c2),
	} {
		if strings.Contains(string(body), enroll["secret"]) {
			t.Fatal("a read API returned the TOTP secret")
		}
		for _, rc := range confirmed.RecoveryCodes {
			if strings.Contains(string(body), rc) {
				t.Fatal("a read API returned a recovery code")
			}
		}
	}
}

func ownerCallAdministrators(t *testing.T, c testAPI) []byte {
	t.Helper()
	r, e := http.NewRequest("GET", c.base+"/api/administrators", nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("X-Requested-With", "aegis-waf")
	r.Header.Set("X-CSRF-Token", c.csrf)
	res, e := c.client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	data, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 200 {
		t.Fatalf("GET /api/administrators: %d", res.StatusCode)
	}
	return data
}

// Disabling MFA requires the current password plus a fresh second factor.
func TestAdministratorMFADisable(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = a
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "mfa-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "mfa-admin", adminOwnerPW)["csrf"].(string)
	var enroll map[string]string
	json.Unmarshal(c.call("POST", "/api/mfa/enroll", map[string]any{}, 200), &enroll)
	secret := adminTestDecodeSecret(t, enroll["secret"])
	var confirmed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	json.Unmarshal(c.call("POST", "/api/mfa/confirm", map[string]string{"code": adminTestTOTP(secret, time.Now().Unix()/30)}, 200), &confirmed)

	// Log in with a recovery code.
	c2 := adminClient(t, s)
	pending := adminLogin(t, c2, "mfa-admin", adminOwnerPW)
	var login map[string]any
	json.Unmarshal(c2.call("POST", "/api/login/mfa", map[string]string{"ticket": pending["ticket"].(string), "code": confirmed.RecoveryCodes[2]}, 200), &login)
	c2.csrf = login["csrf"].(string)

	// Wrong password is refused even with a valid factor.
	c2.call("POST", "/api/mfa/disable", map[string]string{"password": "wrong password entirely", "code": confirmed.RecoveryCodes[3]}, 400)
	// A spent recovery code is not a valid factor.
	c2.call("POST", "/api/mfa/disable", map[string]string{"password": adminOwnerPW, "code": confirmed.RecoveryCodes[2]}, 400)

	// Disabling revokes every session and is audited.
	c2.call("POST", "/api/mfa/disable", map[string]string{"password": adminOwnerPW, "code": confirmed.RecoveryCodes[3]}, 200)
	c2.call("GET", "/api/me", nil, 401)
	if n := adminAuditCount(t, a, "administrator.mfa_disabled"); n != 1 {
		t.Fatalf("mfa_disabled audit rows = %d, want 1", n)
	}

	// Password-only login works again and the spent recovery codes are gone.
	plain := adminLogin(t, c2, "mfa-admin", adminOwnerPW)
	if plain["mfa_required"] == true {
		t.Fatal("MFA must be disabled after the disable flow")
	}
	c2.csrf = plain["csrf"].(string)
	var again struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	reSecret := mustEnrollSecret(t, c2)
	json.Unmarshal(c2.call("POST", "/api/mfa/confirm", map[string]string{"code": adminTestTOTP(adminTestDecodeSecret(t, reSecret), time.Now().Unix()/30)}, 200), &again)
	for _, rc := range again.RecoveryCodes {
		if seen(rc, confirmed.RecoveryCodes) {
			t.Fatal("re-enrollment must issue fresh recovery codes")
		}
	}
}

func seen(needle string, haystack []string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func mustEnrollSecret(t *testing.T, c testAPI) string {
	t.Helper()
	var enroll map[string]string
	if e := json.Unmarshal(c.call("POST", "/api/mfa/enroll", map[string]any{}, 200), &enroll); e != nil {
		t.Fatal(e)
	}
	return enroll["secret"]
}

// Password change requires the current password and revokes every session.
func TestAdministratorPasswordChange(t *testing.T) {
	cfg, a, s := adminFixture(t)
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "pw-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "pw-admin", adminOwnerPW)["csrf"].(string)

	c.call("POST", "/api/password", map[string]string{"current_password": "wrong password entirely", "new_password": adminOwnerPW + "-new"}, 400)
	c.call("POST", "/api/password", map[string]string{"current_password": adminOwnerPW, "new_password": "short"}, 400)
	c.call("POST", "/api/password", map[string]string{"current_password": adminOwnerPW, "new_password": adminOwnerPW + "-new"}, 200)

	c.call("GET", "/api/me", nil, 401)
	c.csrf = adminLogin(t, c, "pw-admin", adminOwnerPW+"-new")["csrf"].(string)
	c.call("GET", "/api/me", nil, 200)
	adminLoginBad(t, c, "pw-admin", adminOwnerPW)
	if n := adminAuditCount(t, a, "administrator.password_changed"); n != 1 {
		t.Fatalf("password_changed audit rows = %d, want 1", n)
	}
}

func adminLoginBad(t *testing.T, c testAPI, username, password string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": username, "password": password})
	r, e := http.NewRequest("POST", c.base+"/api/login", strings.NewReader(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "aegis-waf")
	res, e := c.client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("old password login: got %d want 401", res.StatusCode)
	}
}

// Password recovery: a one-time, expiring token minted host-side (here,
// inserted directly by the test) redeems a password change, clears MFA and
// revokes sessions. There is no unauthenticated token creation path.
func TestAdministratorPasswordReset(t *testing.T) {
	cfg, a, s := adminFixture(t)
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "reset-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "reset-admin", adminOwnerPW)["csrf"].(string)
	var enroll map[string]string
	json.Unmarshal(c.call("POST", "/api/mfa/enroll", map[string]any{}, 200), &enroll)
	c.call("POST", "/api/mfa/confirm", map[string]string{"code": adminTestTOTP(adminTestDecodeSecret(t, enroll["secret"]), time.Now().Unix()/30)}, 200)

	var adminID int64
	if e := a.db.QueryRow(context.Background(), "SELECT id FROM administrators WHERE username=$1", "reset-admin").Scan(&adminID); e != nil {
		t.Fatal(e)
	}
	good := token()
	if _, e := a.db.Exec(context.Background(), "INSERT INTO admin_reset_tokens(token_hash,admin_id,expires_at) VALUES($1,$2,now()+interval '15 minutes')", hash(good), adminID); e != nil {
		t.Fatal(e)
	}
	expired := token()
	if _, e := a.db.Exec(context.Background(), "INSERT INTO admin_reset_tokens(token_hash,admin_id,expires_at) VALUES($1,$2,now()-interval '1 minute')", hash(expired), adminID); e != nil {
		t.Fatal(e)
	}

	c.call("POST", "/api/reset-password", map[string]string{"token": "not-a-real-token", "new_password": adminOwnerPW + "-x"}, 401)
	c.call("POST", "/api/reset-password", map[string]string{"token": expired, "new_password": adminOwnerPW + "-x"}, 401)
	c.call("POST", "/api/reset-password", map[string]string{"token": good, "new_password": "too short"}, 400)
	c.call("POST", "/api/reset-password", map[string]string{"token": good, "new_password": adminOwnerPW + "-reset"}, 200)

	// The reset revoked sessions, cleared MFA and changed the password.
	c.call("GET", "/api/me", nil, 401)
	plain := adminLogin(t, c, "reset-admin", adminOwnerPW+"-reset")
	if plain["mfa_required"] == true {
		t.Fatal("password recovery must clear MFA enrollment")
	}
	c.csrf = plain["csrf"].(string)

	// The token is single-use.
	c2 := adminClient(t, s)
	c2.call("POST", "/api/reset-password", map[string]string{"token": good, "new_password": adminOwnerPW + "-again"}, 401)
	if n := adminAuditCount(t, a, "administrator.password_reset"); n != 1 {
		t.Fatalf("password_reset audit rows = %d, want 1", n)
	}
}

// Session inventory and revocation, effective across replicas on the next
// request: sessions live in PostgreSQL, so a revoke on one replica is visible
// to every other replica immediately.
func TestAdministratorSessions(t *testing.T) {
	cfg, a, s := adminFixture(t)
	b := newTestReplica(t, cfg)
	s2 := httptest.NewServer(b.Management())
	t.Cleanup(s2.Close)

	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "session-admin", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "session-admin", adminOwnerPW)["csrf"].(string)

	// A second concurrent session on the same account.
	c2 := adminClient(t, s)
	c2.csrf = adminLogin(t, c2, "session-admin", adminOwnerPW)["csrf"].(string)

	var sessions []map[string]any
	if e := json.Unmarshal(c.call("GET", "/api/sessions", nil, 200), &sessions); e != nil {
		t.Fatal(e)
	}
	if len(sessions) != 2 {
		t.Fatalf("want two sessions, got %d", len(sessions))
	}
	current := map[int64]bool{}
	for _, row := range sessions {
		if row["ip"] == "" || row["user_agent"] == "" || row["created_at"] == "" || row["last_seen_at"] == "" {
			t.Fatalf("session rows must carry ip, user agent, created and last seen: %v", row)
		}
		id := int64(row["id"].(float64))
		current[id] = row["current"] == true
	}
	if len(current) != 2 {
		t.Fatalf("both sessions must be visible with distinct ids: %v", sessions)
	}

	// The session is valid on the second replica before revocation.
	c2.call("GET", "/api/me", nil, 200)
	onB := testAPI{t, c2.client, s2.URL, c2.csrf}
	onB.call("GET", "/api/me", nil, 200)

	// Revoke the second session; it dies on both replicas, the current one survives.
	var other int64
	for _, row := range sessions {
		if row["current"] != true {
			other = int64(row["id"].(float64))
		}
	}
	c.call("DELETE", fmt.Sprintf("/api/sessions/%d", other), nil, 200)
	c2.call("GET", "/api/me", nil, 401)
	onB.call("GET", "/api/me", nil, 401)
	c.call("GET", "/api/me", nil, 200)
	if n := adminAuditCount(t, a, "session.revoked"); n != 1 {
		t.Fatalf("session.revoked audit rows = %d, want 1", n)
	}

	// Revoke-all takes the remaining session down everywhere.
	c.call("DELETE", "/api/sessions", nil, 200)
	c.call("GET", "/api/me", nil, 401)
	if n := adminAuditCount(t, a, "session.revoked"); n != 2 {
		t.Fatalf("session.revoked audit rows = %d, want 2", n)
	}
}
