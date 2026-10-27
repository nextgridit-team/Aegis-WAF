package app

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
)

type logSettingsInput struct {
	RetentionHours int   `json:"retention_hours"`
	Revision       int64 `json:"revision"`
}

func logSettingsAPI(a *App, mux *http.ServeMux) {
	mux.HandleFunc("GET /api/log-settings", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		var raw []byte
		err := a.db.QueryRow(r.Context(), `SELECT jsonb_build_object(
   'retention_hours',s.retention_hours,'revision',s.revision,
   'last_cleanup_at',m.last_cleanup_at,'last_export_at',m.last_export_at,
   'cleanup_error',m.cleanup_error,'export_error',m.export_error,
   'access_deleted',m.access_deleted,'audit_deleted',m.audit_deleted,'evidence_deleted',m.evidence_deleted,
   'pending_access_export',EXISTS(SELECT 1 FROM access_logs WHERE NOT stdout_emitted),
   'pending_audit_export',EXISTS(SELECT 1 FROM audit_events WHERE NOT stdout_emitted),
   'log_storage_bytes',pg_total_relation_size('access_logs')+pg_total_relation_size('audit_events')+pg_total_relation_size('traffic_evidence'))
   FROM log_settings s JOIN log_maintenance m ON m.id=s.id WHERE s.id`).Scan(&raw)
		if err != nil {
			return err
		}
		var status map[string]any
		if err = json.Unmarshal(raw, &status); err != nil {
			return err
		}
		status["dropped_stdout_logs"] = a.stdoutDropped.Load()
		status["dropped_database_logs"] = a.dropped.Load()
		respond(w, 200, status)
		return nil
	}))
	mux.HandleFunc("PUT /api/log-settings", a.wrap(true, func(w http.ResponseWriter, r *http.Request, actor identity) error {
		var input logSettingsInput
		if err := decode(w, r, &input); err != nil {
			return err
		}
		if input.RetentionHours < 1 || input.RetentionHours > 8760 || input.Revision < 1 {
			return invalid("retention_hours must be 1–8760 and revision is required")
		}
		err := a.change(r.Context(), func(tx pgx.Tx) error {
			tag, err := tx.Exec(r.Context(), "UPDATE log_settings SET retention_hours=$1,revision=revision+1 WHERE id AND revision=$2", input.RetentionHours, input.Revision)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return apiError{409, "log settings changed; reload before saving"}
			}
			return audit(r.Context(), tx, actor.Username, "logging.retention.updated", itoa(int64(input.RetentionHours))+" hours")
		})
		if err != nil {
			return err
		}
		respond(w, 200, map[string]bool{"saved": true})
		return nil
	}))
}
