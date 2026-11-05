package app

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// Keep the displayed start time and the worker's eligibility calculation identical.
// An oversized custom window falls back to one-third of the issued lifetime so
// a shorter-lived replacement cannot cause continuous immediate reissuance.
const certificateRenewalWindowSQL = `CASE
 WHEN c.renew_before_days IS NULL THEN LEAST(interval '30 days',(c.not_after-c.not_before)/3)
 WHEN c.renew_before_days * interval '1 day' >= c.not_after-c.not_before THEN (c.not_after-c.not_before)/3
 ELSE c.renew_before_days * interval '1 day' END`

func (a *App) updateCertificateRenewal(w http.ResponseWriter, r *http.Request, actor identity) error {
	id, err := resourceID(r)
	if err != nil {
		return err
	}
	var input struct {
		Days *int `json:"renew_before_days"`
	}
	if err = decode(w, r, &input); err != nil {
		return err
	}
	if input.Days != nil && (*input.Days < 1 || *input.Days > 365) {
		return invalid("renewal window must be 1–365 whole days, or null for automatic")
	}
	err = a.change(r.Context(), func(tx pgx.Tx) error {
		var origin string
		err := tx.QueryRow(r.Context(), "SELECT origin FROM certificates WHERE id=$1 FOR UPDATE", id).Scan(&origin)
		if errors.Is(err, pgx.ErrNoRows) {
			return apiError{404, "certificate not found"}
		}
		if err != nil {
			return err
		}
		if origin != "acme" {
			return apiError{409, "automatic renewal is available only for ACME-managed certificates"}
		}
		if _, err = tx.Exec(r.Context(), "UPDATE certificates SET renew_before_days=$2,updated_at=now() WHERE id=$1", id, input.Days); err != nil {
			return err
		}
		return audit(r.Context(), tx, actor.Username, "certificate.renewal.updated", strconv.FormatInt(id, 10))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]any{"id": id, "renew_before_days": input.Days})
	return nil
}
