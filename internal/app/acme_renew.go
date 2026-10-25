package app

import (
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strconv"
)

// Manual renewal only queues work. The existing worker coordinates issuance
// across replicas and atomically replaces certificate/key material on success.
func (a *App) renewCertificate(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var origin, challenge string
	var account, credential bool
	e = tx.QueryRow(r.Context(), "SELECT origin,account_id IS NOT NULL,challenge_type,dns_credential_id IS NOT NULL FROM certificates WHERE id=$1 FOR KEY SHARE", id).Scan(&origin, &account, &challenge, &credential)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{404, "certificate not found"}
	}
	if e != nil {
		return e
	}
	if origin != "acme" {
		return apiError{409, "only ACME-managed certificates can be renewed; replace uploaded PEM certificates manually"}
	}
	if !account || challenge == "dns-01" && !credential {
		return apiError{409, "this certificate is missing its saved ACME account or DNS credential"}
	}
	var job int64
	e = tx.QueryRow(r.Context(), "INSERT INTO jobs(certificate_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING id", id).Scan(&job)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{409, "an issuance or renewal job is already active; view its progress or retry the failed job"}
	}
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "acme.renewal.requested", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 202, map[string]any{"id": job, "certificate_id": id, "queued": true})
	return nil
}
