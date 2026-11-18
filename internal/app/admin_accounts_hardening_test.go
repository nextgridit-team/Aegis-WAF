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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Regression tests for the issue #70 hardening findings: the enrollment
// confirmation code is burned, role changes serialize on an advisory
// transaction lock, and a pending login ticket redeems exactly once.

// adminMFAEnrolledTicket drives one administrator through setup, TOTP
// enrollment and confirmation, then collects a fresh password-login ticket.
// It returns the decoded secret, the code that confirmed enrollment and the
// pending ticket.
func adminMFAEnrolledTicket(t *testing.T, cfg Config, s *httptest.Server, username string) (secret []byte, confirmCode, ticket string) {
	t.Helper()
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": username, "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, username, adminOwnerPW)["csrf"].(string)
	var enroll map[string]string
	if e := json.Unmarshal(c.call("POST", "/api/mfa/enroll", map[string]any{}, 200), &enroll); e != nil {
		t.Fatal(e)
	}
	secret = adminTestDecodeSecret(t, enroll["secret"])
	confirmCode = adminTestTOTP(secret, time.Now().Unix()/30)
	var confirmed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if e := json.Unmarshal(c.call("POST", "/api/mfa/confirm", map[string]string{"code": confirmCode}, 200), &confirmed); e != nil {
		t.Fatal(e)
	}
	if len(confirmed.RecoveryCodes) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(confirmed.RecoveryCodes))
	}
	pending := adminLogin(t, adminClient(t, s), username, adminOwnerPW)
	if pending["mfa_required"] != true || pending["ticket"] == "" {
		t.Fatalf("password login must demand the second factor: %v", pending)
	}
	return secret, confirmCode, pending["ticket"].(string)
}

// adminRedeemMFATicket posts one second-factor redemption in its own
// goroutine. Neither a client error nor an unexpected status is fatal here:
// the caller asserts on what came back.
func adminRedeemMFATicket(base, ticket, code string) <-chan adminHTTPResult {
	ch := make(chan adminHTTPResult, 1)
	go func() {
		b, _ := json.Marshal(map[string]string{"ticket": ticket, "code": code})
		r, e := http.NewRequest("POST", base+"/api/login/mfa", bytes.NewReader(b))
		if e != nil {
			ch <- adminHTTPResult{0, e}
			return
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Requested-With", "aegis-waf")
		res, e := (&http.Client{Timeout: 60 * time.Second}).Do(r)
		if e != nil {
			ch <- adminHTTPResult{0, e}
			return
		}
		defer res.Body.Close()
		io.Copy(io.Discard, res.Body)
		ch <- adminHTTPResult{res.StatusCode, nil}
	}()
	return ch
}

type adminHTTPResult struct {
	status int
	err    error
}

// adminTryRoleChange issues one role change and reports the outcome without
// asserting, so callers can fire it from goroutines behind a barrier.
func adminTryRoleChange(ctx context.Context, c testAPI, id int64, role string) adminHTTPResult {
	b, _ := json.Marshal(map[string]string{"role": role})
	r, e := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/api/administrators/%d/role", c.base, id), bytes.NewReader(b))
	if e != nil {
		return adminHTTPResult{0, e}
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "aegis-waf")
	r.Header.Set("X-CSRF-Token", c.csrf)
	res, e := c.client.Do(r)
	if e != nil {
		return adminHTTPResult{0, e}
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return adminHTTPResult{res.StatusCode, nil}
}

// adminLockWaiters counts backends waiting for a table lock on one relation
// in this test's schema. The LOCK TABLE holder itself shows up as granted, so
// only blocked requesters are counted.
func adminLockWaiters(t *testing.T, probe *pgx.Conn, relation string) int {
	t.Helper()
	var n int
	e := probe.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
		 WHERE c.relname=$1 AND c.relnamespace=(SELECT oid FROM pg_namespace WHERE nspname=current_schema())
		 AND l.locktype='relation' AND NOT l.granted`, relation).Scan(&n)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

// adminTransactionWaiters counts backends waiting on another transaction —
// the observable state of a DELETE parked behind a concurrent row lock.
func adminTransactionWaiters(t *testing.T, probe *pgx.Conn) int {
	t.Helper()
	var n int
	if e := probe.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_locks WHERE locktype='transactionid' AND NOT granted`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

// The enrollment confirmation code is burned with the step it verified: the
// same code must not complete the first second-factor login inside its
// ±1-step window. On main the confirmation only verifies against lastStep=0
// and never persists the step, so the identical code immediately signs in —
// issue #70 finding 1.
func TestAdministratorMFAConfirmBurnsCode(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = a
	secret, confirmCode, ticket := adminMFAEnrolledTicket(t, cfg, s, "burn-admin")

	// The confirmation code is spent. A failed attempt only counts one of
	// the ticket's five attempts, so the ticket stays redeemable.
	c2 := adminClient(t, s)
	c2.call("POST", "/api/login/mfa", map[string]string{"ticket": ticket, "code": confirmCode}, 401)

	// A fresh code completes the first login on the same ticket.
	fresh := adminTestTOTP(secret, time.Now().Unix()/30+1)
	var login map[string]any
	if e := json.Unmarshal(c2.call("POST", "/api/login/mfa", map[string]string{"ticket": ticket, "code": fresh}, 200), &login); e != nil {
		t.Fatal(e)
	}
	if login["csrf"] == "" || login["username"] != "burn-admin" {
		t.Fatalf("second-factor login response: %v", login)
	}
}

// Role changes take the workspace-wide advisory transaction lock (700012,
// mirroring the setup flow's 700011): the last-owner guard counts owners in
// READ COMMITTED while locking only the target row, so the lock is what makes
// two simultaneous demotions linear. On main the handler never takes it, so a
// role change completes while another session holds the lock — issue #70
// finding 2.
func TestAdministratorRoleChangeTakesAdvisoryLock(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = a
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "lock-owner", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "lock-owner", adminOwnerPW)["csrf"].(string)
	helper := mustID(t, c.call("POST", "/api/administrators", map[string]string{"username": "lock-helper", "password": adminOperatorPW, "role": "operator"}, 201))

	conn, e := pgx.Connect(context.Background(), cfg.DatabaseURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	if _, e = conn.Exec(context.Background(), "SELECT pg_advisory_lock(700012)"); e != nil {
		t.Fatal(e)
	}
	// While another session holds the advisory lock the role change must
	// not complete; a bounded context stands in for the operator giving up.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	blocked := adminTryRoleChange(ctx, c, helper, "read_only")
	if blocked.err == nil && blocked.status == 200 {
		t.Fatalf("role change completed while the advisory lock was held: status %d", blocked.status)
	}
	// Release the lock; the identical change now succeeds.
	if _, e = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(700012)"); e != nil {
		t.Fatal(e)
	}
	if after := adminTryRoleChange(context.Background(), c, helper, "read_only"); after.err != nil || after.status != 200 {
		t.Fatalf("role change after releasing the advisory lock: status %d err %v, want 200", after.status, after.err)
	}
}

// Two owners demoting each other in the same instant: the advisory lock
// serializes the changes, so the workspace can never end up with zero owners.
// The loser is refused either by the last-owner guard (409) or by wrap()'s
// per-request role re-read once the winner's demotion committed (403).
func TestAdministratorMutualDemotionKeepsOwner(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = cfg
	c := adminClient(t, s)
	c.call("POST", "/api/setup", map[string]string{"username": "mutual-a", "password": adminOwnerPW, "secret": cfg.BootstrapSecret}, 201)
	c.csrf = adminLogin(t, c, "mutual-a", adminOwnerPW)["csrf"].(string)
	idB := mustID(t, c.call("POST", "/api/administrators", map[string]string{"username": "mutual-b", "password": adminOwnerPW, "role": "owner"}, 201))
	var idA int64
	if e := a.db.QueryRow(context.Background(), "SELECT id FROM administrators WHERE username=$1", "mutual-a").Scan(&idA); e != nil {
		t.Fatal(e)
	}
	cb := adminClient(t, s)
	cb.csrf = adminLogin(t, cb, "mutual-b", adminOwnerPW)["csrf"].(string)

	start := make(chan struct{})
	results := make(chan adminHTTPResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		results <- adminTryRoleChange(context.Background(), c, idB, "read_only")
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- adminTryRoleChange(context.Background(), cb, idA, "read_only")
	}()
	close(start)
	wg.Wait()
	close(results)
	succeeded, refused := 0, 0
	for r := range results {
		if r.err != nil {
			t.Fatalf("mutual demotion request failed: %v", r.err)
		}
		switch r.status {
		case 200:
			succeeded++
		case 403, 409:
			refused++
		default:
			t.Fatalf("mutual demotion returned %d, want 200 or 403/409", r.status)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("mutual demotion: %d succeeded and %d refused, want exactly one of each", succeeded, refused)
	}
	var owners int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM administrators WHERE role='owner'").Scan(&owners); e != nil {
		t.Fatal(e)
	}
	if owners != 1 {
		t.Fatalf("owners after mutual demotion = %d, want exactly 1", owners)
	}
}

// A pending login ticket redeems exactly once even under a true concurrent
// double-mint: the DELETE that consumes the ticket must check RowsAffected so
// the redemption that loses the row loses the session. The interleave is
// forced deterministically — a test-held lock on the sessions table parks the
// first redemption between its ticket DELETE and its session INSERT, so the
// second redemption reads the ticket before either side commits.
func TestAdministratorMFATicketSingleRedemption(t *testing.T) {
	cfg, a, s := adminFixture(t)
	_ = cfg
	secret, _, ticket := adminMFAEnrolledTicket(t, cfg, s, "ticket-admin")
	code := adminTestTOTP(secret, time.Now().Unix()/30+1)

	ctx := context.Background()
	conn, e := pgx.Connect(ctx, cfg.DatabaseURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	probe, e := pgx.Connect(ctx, cfg.DatabaseURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { probe.Close(ctx) })
	lockTx, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lockTx.Rollback(ctx) })
	if _, e = lockTx.Exec(ctx, "LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}

	// Park the first redemption on the sessions-table lock: it has consumed
	// the ticket (uncommitted) and now blocks before minting a session.
	first := adminRedeemMFATicket(s.URL, ticket, code)
	eventually(t, func() bool { return adminLockWaiters(t, probe, "sessions") >= 1 })
	// Fire the second redemption; it reads the still-visible ticket, then
	// parks on the first's row lock of the ticket.
	second := adminRedeemMFATicket(s.URL, ticket, code)
	eventually(t, func() bool { return adminTransactionWaiters(t, probe) >= 1 })

	// Release the table lock: the first redemption commits, the second's
	// DELETE wakes up with zero rows affected.
	if e = lockTx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	r1, r2 := <-first, <-second
	if r1.err != nil || r2.err != nil {
		t.Fatalf("redemption requests failed: %v / %v", r1.err, r2.err)
	}
	statuses := []int{r1.status, r2.status}
	sort.Ints(statuses)
	if statuses[0] != 200 || statuses[1] != 401 {
		t.Fatalf("concurrent redemptions of one ticket: statuses %v, want exactly one 200 and one 401", statuses)
	}
	var sessions int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&sessions); e != nil {
		t.Fatal(e)
	}
	if sessions != 1 {
		t.Fatalf("sessions minted from one ticket = %d, want exactly 1", sessions)
	}
}
