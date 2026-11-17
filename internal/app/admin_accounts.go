package app

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Administrator roles. The matrix is enforced in wrap() before any handler
// runs, mirroring the operation-domain boundaries the MCP scope mapping
// (agentScopeFor) draws: reads are available to every role, workspace
// mutations require operator, and credential minting plus administrator
// management are owner-only. Self-service account routes (password, MFA,
// own sessions) stay open to every authenticated administrator.
const (
	adminRouteOwner     = "owner"
	adminRouteOperator  = "operator"
	adminRouteReadOnly  = "read_only"
	recoveryCodeLength  = 16
	recoveryCodeCount   = 10
	mfaTicketLifetime   = 5 * time.Minute
	mfaTicketMaxAttempt = 5
	resetTokenMaxAge    = time.Hour
)

var recoveryCodeAlphabet = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func validAdministratorRole(role string) bool {
	return role == adminRouteOwner || role == adminRouteOperator || role == adminRouteReadOnly
}

func roleAtLeast(role, required string) bool {
	rank := map[string]int{adminRouteReadOnly: 0, adminRouteOperator: 1, adminRouteOwner: 2}
	return rank[role] >= rank[required]
}

// adminRouteRole names the minimum role a route demands. Patterns are the
// ServeMux registration strings, so wildcard routes are matched by their
// {id} form. Unauthenticated routes never reach this check.
func adminRouteRole(pattern string) string {
	method, path, _ := strings.Cut(pattern, " ")
	switch pattern {
	case "GET /api/me", "GET /api/status", "GET /api/metrics", "POST /api/logout",
		"POST /api/password", "POST /api/mfa/enroll", "POST /api/mfa/confirm", "POST /api/mfa/disable",
		"GET /api/sessions", "DELETE /api/sessions", "DELETE /api/sessions/{id}":
		return adminRouteReadOnly
	}
	if path == "/api/administrators" || strings.HasPrefix(path, "/api/administrators/") {
		return adminRouteOwner
	}
	// Agent keys mint workspace-wide credentials and the agent endpoint
	// gates every MCP client: both are account authority, not operations.
	if path == "/api/agent-access" || path == "/api/agent-keys" || strings.HasPrefix(path, "/api/agent-keys/") || strings.HasPrefix(path, "/api/agent-access/") {
		return adminRouteOwner
	}
	if method == "GET" || method == "HEAD" {
		return adminRouteReadOnly
	}
	return adminRouteOperator
}

func adminAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("POST /api/login/mfa", a.wrap(false, a.loginMFA))
	m.HandleFunc("POST /api/reset-password", a.wrap(false, a.resetPassword))
	m.HandleFunc("POST /api/password", a.wrap(true, a.changePassword))
	m.HandleFunc("GET /api/sessions", a.wrap(true, a.listSessions))
	m.HandleFunc("DELETE /api/sessions", a.wrap(true, a.revokeAllSessions))
	m.HandleFunc("DELETE /api/sessions/{id}", a.wrap(true, a.revokeSession))
	m.HandleFunc("POST /api/mfa/enroll", a.wrap(true, a.mfaEnroll))
	m.HandleFunc("POST /api/mfa/confirm", a.wrap(true, a.mfaConfirm))
	m.HandleFunc("POST /api/mfa/disable", a.wrap(true, a.mfaDisable))
	m.HandleFunc("GET /api/administrators", a.wrap(true, a.listAdministrators))
	m.HandleFunc("POST /api/administrators", a.wrap(true, a.createAdministrator))
	m.HandleFunc("PUT /api/administrators/{id}/role", a.wrap(true, a.changeAdministratorRole))
}

func totpAAD(id int64, pending bool) string {
	if pending {
		return fmt.Sprintf("administrator-totp-pending:%d", id)
	}
	return fmt.Sprintf("administrator-totp:%d", id)
}

// newRecoveryCode mints one sixteen-character lowercase code. Codes are
// stored only as bcrypt hashes and shown exactly once, at enrollment.
func newRecoveryCode() string {
	b := make([]byte, 10)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return recoveryCodeAlphabet.EncodeToString(b)
}

func isRecoveryCodeShape(code string) bool {
	if len(code) != recoveryCodeLength {
		return false
	}
	for _, c := range code {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz234567", c) {
			return false
		}
	}
	return true
}

// verifySecondFactor proves possession of one remaining factor for an
// administrator inside an open transaction: a fresh TOTP code (replay
// rejected against lastStep, returning the accepted step for the caller to
// persist once its guarded mutation commits) or an unused recovery code
// (consumed atomically here). Codes are never logged or echoed.
func (a *App) verifySecondFactor(ctx context.Context, tx pgx.Tx, adminID int64, code string) (ok, recovery bool, step int64, e error) {
	if isRecoveryCodeShape(strings.ToLower(code)) {
		rows, er := tx.Query(ctx, "SELECT id,code_hash FROM admin_recovery_codes WHERE admin_id=$1 AND NOT used ORDER BY id", adminID)
		if er != nil {
			return false, false, 0, er
		}
		type candidate struct {
			id   int64
			hash string
		}
		candidates, er := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
			var c candidate
			return c, row.Scan(&c.id, &c.hash)
		})
		if er != nil {
			return false, false, 0, er
		}
		// Bcrypt comparisons are independent and CPU-bound; running them
		// concurrently bounds a wrong-code attempt to roughly one hash
		// instead of the whole list. Every stored code is compared, so the
		// outcome does not depend on which goroutine finishes first.
		matches := make([]bool, len(candidates))
		var wg sync.WaitGroup
		for n, c := range candidates {
			wg.Add(1)
			go func(n int, c candidate) {
				defer wg.Done()
				matches[n] = bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(strings.ToLower(code))) == nil
			}(n, c)
		}
		wg.Wait()
		for n, c := range candidates {
			if !matches[n] {
				continue
			}
			tag, er := tx.Exec(ctx, "UPDATE admin_recovery_codes SET used=true,used_at=now() WHERE id=$1 AND NOT used", c.id)
			if er != nil {
				return false, false, 0, er
			}
			if tag.RowsAffected() == 1 {
				return true, true, 0, nil
			}
		}
		return false, false, 0, nil
	}
	var cipher []byte
	var keyID string
	var lastStep int64
	if e = tx.QueryRow(ctx, "SELECT totp_secret_cipher,totp_key_id,totp_last_step FROM administrators WHERE id=$1", adminID).Scan(&cipher, &keyID, &lastStep); e != nil {
		return false, false, 0, e
	}
	if len(cipher) == 0 {
		return false, false, 0, nil
	}
	secret, e := open(a.cfg.Key, keyID+":"+totpAAD(adminID, false), cipher)
	if e != nil {
		return false, false, 0, e
	}
	step, ok = verifyTOTP(secret, code, time.Now(), lastStep)
	return ok, false, step, nil
}

// persistTOTPStep records the newest accepted TOTP step so a code cannot be
// replayed; callers invoke it in the same transaction as the mutation the
// factor guarded.
func persistTOTPStep(ctx context.Context, tx pgx.Tx, adminID, step int64) error {
	_, e := tx.Exec(ctx, "UPDATE administrators SET totp_last_step=$2 WHERE id=$1 AND $2>totp_last_step", adminID, step)
	return e
}

// revokeAllAdminSessions invalidates every session of one administrator and
// audits it transactionally with the mutation that caused it (password or MFA
// change, password recovery).
func revokeAllAdminSessions(ctx context.Context, tx pgx.Tx, actor string, adminID int64) error {
	tag, e := tx.Exec(ctx, "DELETE FROM sessions WHERE admin_id=$1", adminID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() > 0 {
		return audit(ctx, tx, actor, "session.revoked", "all")
	}
	return nil
}

func (a *App) loginMFA(w http.ResponseWriter, r *http.Request, _ identity) error {
	if e := a.authLimit(r); e != nil {
		return e
	}
	var b struct {
		Ticket, Code string
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if len(b.Ticket) > 64 || len(b.Code) > 64 {
		return apiError{401, "invalid or expired login ticket"}
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var adminID, attempts int64
	var username string
	var expiresAt time.Time
	e = tx.QueryRow(r.Context(), "SELECT p.admin_id,p.attempts,p.expires_at,a.username FROM admin_mfa_pending p JOIN administrators a ON a.id=p.admin_id WHERE p.token_hash=$1", hash(b.Ticket)).Scan(&adminID, &attempts, &expiresAt, &username)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{401, "invalid or expired login ticket"}
	}
	if e != nil {
		return e
	}
	if time.Now().After(expiresAt) || attempts >= mfaTicketMaxAttempt {
		if _, e = tx.Exec(r.Context(), "DELETE FROM admin_mfa_pending WHERE token_hash=$1", hash(b.Ticket)); e != nil {
			return e
		}
		return txCommit(r.Context(), tx, apiError{401, "invalid or expired login ticket"})
	}
	ok, recovery, step, e := a.verifySecondFactor(r.Context(), tx, adminID, b.Code)
	if e != nil {
		return e
	}
	if !ok {
		if _, e = tx.Exec(r.Context(), "UPDATE admin_mfa_pending SET attempts=attempts+1 WHERE token_hash=$1", hash(b.Ticket)); e != nil {
			return e
		}
		if attempts+1 >= mfaTicketMaxAttempt {
			if _, e = tx.Exec(r.Context(), "DELETE FROM admin_mfa_pending WHERE token_hash=$1", hash(b.Ticket)); e != nil {
				return e
			}
		}
		if e = tx.Commit(r.Context()); e != nil {
			return e
		}
		return apiError{401, "invalid code"}
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM admin_mfa_pending WHERE token_hash=$1", hash(b.Ticket)); e != nil {
		return e
	}
	if !recovery {
		if e = persistTOTPStep(r.Context(), tx, adminID, step); e != nil {
			return e
		}
	}
	csrf, e := a.createAdminSession(r.Context(), r, tx, adminID)
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, username, "login.succeeded", "management"); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	http.SetCookie(w, sessionCookie(r, csrf.token, 43200))
	respond(w, 200, map[string]string{"csrf": csrf.csrf, "username": username, "role": a.adminRoleOf(r.Context(), adminID)})
	return nil
}

// adminRoleOf reads one administrator's role for sign-in responses. Every
// request re-reads it from the session join, so this is presentation only.
func (a *App) adminRoleOf(ctx context.Context, adminID int64) string {
	var role string
	if e := a.db.QueryRow(ctx, "SELECT role FROM administrators WHERE id=$1", adminID).Scan(&role); e != nil {
		return ""
	}
	return role
}

// txCommit commits and returns a supplied API error, so failure paths can
// persist their attempt accounting before responding.
func txCommit(ctx context.Context, tx pgx.Tx, failure error) error {
	if e := tx.Commit(ctx); e != nil {
		return e
	}
	return failure
}

type adminSession struct {
	token, csrf string
}

// createAdminSession mints the session row inside an open transaction; the
// caller commits and then sets the cookie on success.
func (a *App) createAdminSession(ctx context.Context, r *http.Request, tx pgx.Tx, adminID int64) (adminSession, error) {
	t, csrf := token(), token()
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	agent := truncateUTF8(strings.ToValidUTF8(strings.ReplaceAll(r.UserAgent(), "\x00", ""), "�"), 300)
	if _, e := tx.Exec(ctx, "INSERT INTO sessions(token_hash,admin_id,csrf,expires_at,ip,user_agent) VALUES($1,$2,$3,now()+interval '12 hours',$4,$5)", hash(t), adminID, csrf, peer, agent); e != nil {
		return adminSession{}, e
	}
	return adminSession{t, csrf}, nil
}

func (a *App) mfaEnroll(w http.ResponseWriter, r *http.Request, i identity) error {
	var enrolled bool
	if e := a.db.QueryRow(r.Context(), "SELECT mfa_enrolled_at IS NOT NULL FROM administrators WHERE id=$1", i.ID).Scan(&enrolled); e != nil {
		return e
	}
	if enrolled {
		return apiError{409, "MFA is already enabled; disable it before re-enrolling"}
	}
	raw, encoded := newTOTPSecret()
	cipher, e := seal(a.cfg.Key, a.cfg.KeyID+":"+totpAAD(i.ID, true), raw)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET totp_pending_cipher=$2,totp_pending_key_id=$3 WHERE id=$1", i.ID, cipher, a.cfg.KeyID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	// The secret is shown exactly once, here; every later read returns only
	// the enabled state.
	respond(w, 200, map[string]string{"secret": encoded, "uri": otpauthURI(i.Username, encoded)})
	return nil
}

func (a *App) mfaConfirm(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Code string
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var keyID string
	var pendingCipher []byte
	if e = tx.QueryRow(r.Context(), "SELECT totp_pending_cipher,totp_pending_key_id FROM administrators WHERE id=$1 FOR UPDATE", i.ID).Scan(&pendingCipher, &keyID); e != nil {
		return e
	}
	if len(pendingCipher) == 0 {
		return apiError{400, "start enrollment before confirming"}
	}
	secret, e := open(a.cfg.Key, keyID+":"+totpAAD(i.ID, true), pendingCipher)
	if e != nil {
		return e
	}
	if _, ok := verifyTOTP(secret, b.Code, time.Now(), 0); !ok {
		return apiError{400, "invalid verification code"}
	}
	// Re-seal under the active-state AAD: the pending and enrolled ciphers
	// are deliberately not interchangeable.
	active, e := seal(a.cfg.Key, a.cfg.KeyID+":"+totpAAD(i.ID, false), secret)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET totp_secret_cipher=$2,totp_key_id=$3,mfa_enrolled_at=now(),totp_pending_cipher=NULL,totp_pending_key_id='' WHERE id=$1", i.ID, active, a.cfg.KeyID); e != nil {
		return e
	}
	codes := make([]string, recoveryCodeCount)
	hashes := make([]string, recoveryCodeCount)
	for n := range codes {
		codes[n] = newRecoveryCode()
	}
	// Hashing ten codes at cost 12 takes seconds sequentially; hashing them
	// concurrently bounds enrollment to roughly a single hash while the
	// per-code strength stays identical to administrator passwords.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hashErr error
	for n := range codes {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hashed, e := bcrypt.GenerateFromPassword([]byte(codes[n]), 12)
			if e != nil {
				mu.Lock()
				if hashErr == nil {
					hashErr = e
				}
				mu.Unlock()
				return
			}
			hashes[n] = string(hashed)
		}(n)
	}
	wg.Wait()
	if hashErr != nil {
		return hashErr
	}
	for n := range codes {
		if _, e = tx.Exec(r.Context(), "INSERT INTO admin_recovery_codes(admin_id,code_hash) VALUES($1,$2)", i.ID, hashes[n]); e != nil {
			return e
		}
	}
	if e = revokeAllAdminSessions(r.Context(), tx, i.Username, i.ID); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "administrator.mfa_enrolled", strconv.FormatInt(i.ID, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	// Recovery codes are displayed exactly once, here.
	respond(w, 200, map[string]any{"recovery_codes": codes})
	return nil
}

func (a *App) mfaDisable(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Password, Code string
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var pw string
	if e = tx.QueryRow(r.Context(), "SELECT password_hash FROM administrators WHERE id=$1 FOR UPDATE", i.ID).Scan(&pw); e != nil {
		return e
	}
	if bcrypt.CompareHashAndPassword([]byte(pw), []byte(b.Password)) != nil {
		return apiError{400, "current password rejected"}
	}
	ok, recovery, step, e := a.verifySecondFactor(r.Context(), tx, i.ID, b.Code)
	if e != nil {
		return e
	}
	if !ok {
		return apiError{400, "invalid verification code"}
	}
	if !recovery {
		if e = persistTOTPStep(r.Context(), tx, i.ID, step); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET totp_secret_cipher=NULL,totp_key_id='',mfa_enrolled_at=NULL,totp_last_step=0,totp_pending_cipher=NULL,totp_pending_key_id='' WHERE id=$1", i.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM admin_recovery_codes WHERE admin_id=$1", i.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM admin_mfa_pending WHERE admin_id=$1", i.ID); e != nil {
		return e
	}
	if e = revokeAllAdminSessions(r.Context(), tx, i.Username, i.ID); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "administrator.mfa_disabled", strconv.FormatInt(i.ID, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"disabled": true})
	return nil
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if len(b.NewPassword) < 14 || len(b.NewPassword) > 72 {
		return invalid("new password must be 14–72 bytes")
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var pw string
	if e = tx.QueryRow(r.Context(), "SELECT password_hash FROM administrators WHERE id=$1 FOR UPDATE", i.ID).Scan(&pw); e != nil {
		return e
	}
	if bcrypt.CompareHashAndPassword([]byte(pw), []byte(b.CurrentPassword)) != nil {
		return apiError{400, "current password rejected"}
	}
	if bcrypt.CompareHashAndPassword([]byte(pw), []byte(b.NewPassword)) == nil {
		return invalid("choose a new password different from the current one")
	}
	hashed, e := bcrypt.GenerateFromPassword([]byte(b.NewPassword), 12)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET password_hash=$2 WHERE id=$1", i.ID, string(hashed)); e != nil {
		return e
	}
	if e = revokeAllAdminSessions(r.Context(), tx, i.Username, i.ID); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "administrator.password_changed", strconv.FormatInt(i.ID, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"changed": true})
	return nil
}

// resetPassword redeems a one-time, expiring token minted host-side by
// CreateAdminResetToken. There is no unauthenticated token creation: an
// unauthenticated caller can only guess. Redemption rotates the password,
// clears MFA (the recovery path for a lost authenticator) and revokes every
// session.
func (a *App) resetPassword(w http.ResponseWriter, r *http.Request, _ identity) error {
	if e := a.authLimit(r); e != nil {
		return e
	}
	var b struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if len(b.NewPassword) < 14 || len(b.NewPassword) > 72 {
		return invalid("new password must be 14–72 bytes")
	}
	if len(b.Token) > 64 {
		return apiError{401, "invalid or expired reset token"}
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var adminID int64
	var expiresAt time.Time
	e = tx.QueryRow(r.Context(), "SELECT admin_id,expires_at FROM admin_reset_tokens WHERE token_hash=$1 AND NOT used FOR UPDATE", hash(b.Token)).Scan(&adminID, &expiresAt)
	if errors.Is(e, pgx.ErrNoRows) || (e == nil && time.Now().After(expiresAt)) {
		return apiError{401, "invalid or expired reset token"}
	}
	if e != nil {
		return e
	}
	hashed, e := bcrypt.GenerateFromPassword([]byte(b.NewPassword), 12)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET password_hash=$2,totp_secret_cipher=NULL,totp_key_id='',mfa_enrolled_at=NULL,totp_last_step=0,totp_pending_cipher=NULL,totp_pending_key_id='' WHERE id=$1", adminID, string(hashed)); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE admin_reset_tokens SET used=true,used_at=now() WHERE token_hash=$1", hash(b.Token)); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM admin_recovery_codes WHERE admin_id=$1", adminID); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM admin_mfa_pending WHERE admin_id=$1", adminID); e != nil {
		return e
	}
	var username string
	if e = tx.QueryRow(r.Context(), "SELECT username FROM administrators WHERE id=$1", adminID).Scan(&username); e != nil {
		return e
	}
	if e = revokeAllAdminSessions(r.Context(), tx, username, adminID); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, username, "administrator.password_reset", strconv.FormatInt(adminID, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"reset": true})
	return nil
}

// CreateAdminResetToken mints a single-use administrator password-reset
// token with a bounded lifetime. It exists for the host-side recovery
// command: a process that already holds database access can start a
// recovery; an unauthenticated network caller cannot create tokens. The
// plaintext token is returned once — only its hash is stored — and the
// generation is audited.
func CreateAdminResetToken(ctx context.Context, db *pgxpool.Pool, username string, ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > resetTokenMaxAge {
		return "", fmt.Errorf("reset token lifetime must be between one second and one hour")
	}
	tx, e := db.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var adminID int64
	e = tx.QueryRow(ctx, "SELECT id FROM administrators WHERE username=$1", username).Scan(&adminID)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", fmt.Errorf("administrator %q not found", username)
	}
	if e != nil {
		return "", e
	}
	t := token()
	if _, e = tx.Exec(ctx, "DELETE FROM admin_reset_tokens WHERE expires_at<now()"); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO admin_reset_tokens(token_hash,admin_id,expires_at) VALUES($1,$2,$3)", hash(t), adminID, time.Now().Add(ttl)); e != nil {
		return "", e
	}
	if e = audit(ctx, tx, "reset-command", "administrator.reset_token_created", strconv.FormatInt(adminID, 10)); e != nil {
		return "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", e
	}
	return t, nil
}

func (a *App) listSessions(w http.ResponseWriter, r *http.Request, i identity) error {
	c, _ := r.Cookie("aegis_waf_session")
	var data []byte
	e := a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT s.id,s.ip,s.user_agent,s.created_at,s.last_seen_at,(s.token_hash=$2) AS current FROM sessions s WHERE s.admin_id=$1 AND s.expires_at>now() ORDER BY s.last_seen_at DESC) x", i.ID, hash(c.Value)).Scan(&data)
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(data))
	return nil
}

func (a *App) revokeSession(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "DELETE FROM sessions WHERE id=$1 AND admin_id=$2", id, i.ID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "session not found"}
	}
	if e = audit(r.Context(), tx, i.Username, "session.revoked", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"revoked": true})
	return nil
}

func (a *App) revokeAllSessions(w http.ResponseWriter, r *http.Request, i identity) error {
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "DELETE FROM sessions WHERE admin_id=$1", i.ID)
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "session.revoked", "all"); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"revoked": tag.RowsAffected()})
	return nil
}

func (a *App) listAdministrators(w http.ResponseWriter, r *http.Request, _ identity) error {
	var data []byte
	e := a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT id,username,role,mfa_enrolled_at IS NOT NULL AS mfa_enabled FROM administrators ORDER BY id) x").Scan(&data)
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(data))
	return nil
}

func (a *App) createAdministrator(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Username, Password, Role string
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if len(b.Username) < 3 || len(b.Username) > 64 || strings.TrimSpace(b.Username) != b.Username || len(b.Password) < 14 || len(b.Password) > 72 {
		return invalid("username must be 3–64 characters; password must be 14–72 bytes")
	}
	if !validAdministratorRole(b.Role) {
		return invalid("role must be owner, operator or read_only")
	}
	hashed, e := bcrypt.GenerateFromPassword([]byte(b.Password), 12)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var exists bool
	if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM administrators WHERE username=$1)", b.Username).Scan(&exists); e != nil {
		return e
	}
	if exists {
		return apiError{409, "username already exists"}
	}
	var id int64
	if e = tx.QueryRow(r.Context(), "INSERT INTO administrators(username,password_hash,role) VALUES($1,$2,$3) RETURNING id", b.Username, string(hashed), b.Role).Scan(&id); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "administrator.created", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 201, map[string]int64{"id": id})
	return nil
}

func (a *App) changeAdministratorRole(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	var b struct {
		Role string
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if !validAdministratorRole(b.Role) {
		return invalid("role must be owner, operator or read_only")
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if id == i.ID {
		return invalid("an administrator cannot change their own role")
	}
	var current string
	if e = tx.QueryRow(r.Context(), "SELECT role FROM administrators WHERE id=$1 FOR UPDATE", id).Scan(&current); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return apiError{404, "administrator not found"}
		}
		return e
	}
	if b.Role != adminRouteOwner {
		var owners int
		if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM administrators WHERE role='owner' AND id<>$1", id).Scan(&owners); e != nil {
			return e
		}
		if owners == 0 {
			return apiError{409, "the workspace must keep at least one owner"}
		}
	}
	if _, e = tx.Exec(r.Context(), "UPDATE administrators SET role=$2 WHERE id=$1", id, b.Role); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "administrator.role_changed", fmt.Sprintf("%d:%s->%s", id, current, b.Role)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 200, map[string]any{"id": id, "role": b.Role})
	return nil
}
