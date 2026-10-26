package app

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type rateStateInput struct {
	rateStateSettings
	Revision      int64  `json:"revision"`
	Password      string `json:"password"`
	ClearPassword bool   `json:"clear_password"`
}

func (a *App) candidateRateState(current storedRateState, input rateStateInput) (storedRateState, error) {
	settings, e := normalizeRateState(input.rateStateSettings)
	if e != nil {
		return current, e
	}
	if len(input.Password) > 4096 {
		return current, invalid("rate-state password too long")
	}
	if input.ClearPassword && input.Password != "" {
		return current, invalid("provide a password or clear it")
	}
	if input.Revision != current.Revision {
		return current, apiError{409, "rate state changed; reload before saving"}
	}
	changed := settings.Address != current.Settings.Address || settings.Username != current.Settings.Username || settings.TLS != current.Settings.TLS
	if changed && len(current.Cipher) > 0 && input.Password == "" && !input.ClearPassword {
		return current, invalid("supply or explicitly clear credentials when changing the backend address, username or TLS")
	}
	current.Settings = settings
	if input.ClearPassword {
		current.Cipher = nil
		current.KeyID = ""
	}
	if input.Password != "" {
		current.Cipher, e = seal(a.cfg.Key, a.cfg.KeyID+":rate-state-password", []byte(input.Password))
		current.KeyID = a.cfg.KeyID
	}
	return current, e
}
func rateStateAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/rate-state", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		stored, e := readRateState(r.Context(), a.db)
		if e != nil {
			return e
		}
		loadedRevision := int64(0)
		var failures uint64
		if s := a.active.Load(); s != nil && s.rateState != nil {
			loadedRevision = s.rateState.stored.Revision
			failures = s.rateState.failures.Load()
		}
		respond(w, 200, map[string]any{"settings": stored.Settings, "revision": stored.Revision, "has_password": len(stored.Cipher) > 0, "loaded_revision": loadedRevision, "backend_failures": failures})
		return nil
	}))
	m.HandleFunc("PUT /api/rate-state", a.wrap(true, a.saveRateState))
	m.HandleFunc("POST /api/rate-state/test", a.wrap(true, a.testRateState))
}
func (a *App) saveRateState(w http.ResponseWriter, r *http.Request, actor identity) error {
	var input rateStateInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	e := a.change(r.Context(), func(tx pgx.Tx) error {
		stored, e := readRateState(r.Context(), tx)
		if e != nil {
			return e
		}
		candidate, e := a.candidateRateState(stored, input)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(candidate.Settings)
		if _, e = tx.Exec(r.Context(), "UPDATE rate_state SET settings=$1,password_cipher=$2,key_id=$3,revision=revision+1 WHERE id", raw, candidate.Cipher, candidate.KeyID); e != nil {
			return e
		}
		return audit(r.Context(), tx, actor.Username, "rate_state.updated", candidate.Settings.Backend)
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"saved": true})
	return nil
}
func (a *App) testRateState(w http.ResponseWriter, r *http.Request, actor identity) error {
	var input rateStateInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	stored, e := readRateState(r.Context(), a.db)
	if e != nil {
		return e
	}
	candidate, e := a.candidateRateState(stored, input)
	if e != nil {
		return e
	}
	if candidate.Settings.Backend != "redis" {
		respond(w, 200, map[string]bool{"connected": true})
		return nil
	}
	runtime, e := a.compileRateState(candidate)
	if e != nil {
		return e
	}
	// A separate short-lived client tests draft credentials without taking tokens
	// or changing the live backend. Ping errors never expose credentials.
	client := runtime.newClient()
	defer client.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if e = client.Ping(ctx).Err(); e != nil {
		return apiError{502, "could not connect/authenticate to the rate-state backend"}
	}
	if _, e = a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES($1,'rate_state.tested','redis')", actor.Username); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"connected": true})
	return nil
}
