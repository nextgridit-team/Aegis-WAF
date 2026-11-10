package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func readIdentityProvider(ctx context.Context, q rowQuerier, id int64) (storedIdentityProvider, error) {
	p := storedIdentityProvider{ID: id}
	var raw []byte
	e := q.QueryRow(ctx, "SELECT settings,revision,secret_cipher,key_id FROM identity_providers WHERE id=$1", id).Scan(&raw, &p.Revision, &p.Cipher, &p.KeyID)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, apiError{404, "identity provider not found"}
	}
	if e != nil {
		return p, e
	}
	e = json.Unmarshal(raw, &p.Settings)
	p.HasSecret = len(p.Cipher) > 0
	return p, e
}
func readApplicationAccess(ctx context.Context, q rowQuerier, id int64) (applicationAccess, error) {
	out := applicationAccess{SiteID: id, Settings: applicationAccessSettings{AllowedGroups: []string{}, SessionMinutes: 30}}
	var raw []byte
	e := q.QueryRow(ctx, "SELECT a.settings,coalesce(a.revision,0) FROM sites s LEFT JOIN application_access a ON a.site_id=s.id WHERE s.id=$1", id).Scan(&raw, &out.Revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, apiError{404, "application not found"}
	}
	if e != nil {
		return out, e
	}
	if len(raw) > 0 {
		e = json.Unmarshal(raw, &out.Settings)
	}
	return out, e
}
func (a *App) identitySecret(p storedIdentityProvider) (string, error) {
	if len(p.Cipher) == 0 {
		return "", nil
	}
	if p.KeyID != a.cfg.KeyID {
		return "", errors.New("identity provider key unavailable")
	}
	raw, e := open(a.cfg.Key, p.KeyID+":identity-provider:"+strconv.FormatInt(p.ID, 10), p.Cipher)
	return string(raw), e
}
func (a *App) saveIdentityProvider(w http.ResponseWriter, r *http.Request, actor identity) error {
	var input identityProviderInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	settings, e := normalizeIdentityProvider(input.identityProviderSettings)
	if e != nil {
		return e
	}
	if len(input.Secret) > 8192 || input.ClearSecret && input.Secret != "" {
		return invalid("provide a secret of at most 8192 bytes, or explicitly clear it")
	}
	var id int64
	if r.PathValue("id") != "" {
		id, e = resourceID(r)
		if e != nil {
			return e
		}
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		var old storedIdentityProvider
		if id != 0 {
			var err error
			old, err = readIdentityProvider(ctx, tx, id)
			if err != nil {
				return err
			}
			if old.Revision != input.Revision {
				return apiError{409, "provider changed; reload before saving"}
			}
			if old.Settings.Type != settings.Type {
				return invalid("create a new provider to change its type")
			}
			before, after := "", ""
			if settings.Type == "oidc" {
				before = old.Settings.OIDC.Issuer + "\n" + old.Settings.OIDC.ClientID
				after = settings.OIDC.Issuer + "\n" + settings.OIDC.ClientID
			} else {
				before = old.Settings.LDAP.URL + "\n" + old.Settings.LDAP.BindDN
				after = settings.LDAP.URL + "\n" + settings.LDAP.BindDN
			}
			if old.HasSecret && (before != after || old.Settings.CAPEM != settings.CAPEM) && input.Secret == "" && !input.ClearSecret {
				return invalid("supply the secret again when changing the provider address, client/bind identity or CA")
			}
		} else {
			if input.Revision != 0 {
				return invalid("new providers require revision 0")
			}
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM identity_providers").Scan(&count); err != nil {
				return err
			}
			if count >= 20 {
				return invalid("at most 20 identity providers")
			}
		}
		if settings.Type == "ldap" && (input.ClearSecret || input.Secret == "" && !old.HasSecret) {
			return invalid("LDAP requires a nonempty service bind password")
		}
		raw, _ := json.Marshal(settings)
		if id == 0 {
			if err := tx.QueryRow(ctx, "INSERT INTO identity_providers(settings) VALUES($1) RETURNING id", raw).Scan(&id); err != nil {
				return err
			}
		}
		cipher, keyID := old.Cipher, old.KeyID
		if input.ClearSecret {
			cipher = nil
			keyID = ""
		}
		if input.Secret != "" {
			var err error
			keyID = a.cfg.KeyID
			cipher, err = seal(a.cfg.Key, keyID+":identity-provider:"+strconv.FormatInt(id, 10), []byte(input.Secret))
			if err != nil {
				return err
			}
		}
		revision := old.Revision + 1
		if _, err := tx.Exec(ctx, "UPDATE identity_providers SET settings=$2,secret_cipher=$3,key_id=$4,revision=$5 WHERE id=$1", id, raw, cipher, keyID, revision); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM application_sessions WHERE provider_id=$1", id); err != nil {
			return err
		}
		return audit(ctx, tx, actor.Username, "identity_provider.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) saveApplicationAccess(w http.ResponseWriter, r *http.Request, actor identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	var input applicationAccessInput
	if e = decode(w, r, &input); e != nil {
		return e
	}
	settings, e := normalizeApplicationAccess(input.applicationAccessSettings)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		old, err := readApplicationAccess(ctx, tx, id)
		if err != nil {
			return err
		}
		if old.Revision != input.Revision {
			return apiError{409, "application access changed; reload before saving"}
		}
		if settings.ProviderID != 0 {
			p, err := readIdentityProvider(ctx, tx, settings.ProviderID)
			if err != nil {
				return err
			}
			if settings.Enabled && !p.Settings.Enabled {
				return invalid("enable the identity provider before assigning required access")
			}
			if p.Settings.Type == "ldap" {
				for _, g := range settings.AllowedGroups {
					if !validGroupDN(g) {
						return invalid("LDAP allowed_groups must use group distinguished names")
					}
				}
			}
		}
		if settings.PublicOrigin != "" {
			var hosts []string
			if err := tx.QueryRow(ctx, "SELECT hostnames FROM sites WHERE id=$1", id).Scan(&hosts); err != nil {
				return err
			}
			u, _ := url.Parse(settings.PublicOrigin)
			matched := false
			for _, host := range hosts {
				if host == requestHost(u.Host) {
					matched = true
				}
			}
			if !matched {
				return invalid("public_origin must match one of this application's hostnames")
			}
		}
		raw, _ := json.Marshal(settings)
		if _, err := tx.Exec(ctx, "INSERT INTO application_access(site_id,provider_id,settings) VALUES($1,nullif($2::bigint,0),$3) ON CONFLICT(site_id) DO UPDATE SET provider_id=excluded.provider_id,settings=excluded.settings,revision=application_access.revision+1", id, settings.ProviderID, raw); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM application_sessions WHERE site_id=$1", id); err != nil {
			return err
		}
		return audit(ctx, tx, actor.Username, "application_access.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"saved": true})
	return nil
}
func applicationAccessAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("POST /api/identity-providers/{id}/test", a.wrap(true, a.testIdentityProvider))
	m.HandleFunc("POST /api/identity-providers/{id}/groups", a.wrap(true, a.identityGroups))
	m.HandleFunc("GET /api/identity-providers/presets", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		respond(w, 200, identityProviderPresets())
		return nil
	}))
	m.HandleFunc("GET /api/identity-providers", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, `SELECT p.id,p.settings,p.revision,(p.secret_cipher IS NOT NULL) AS has_secret,coalesce((SELECT jsonb_agg(jsonb_build_object('id',s.id,'name',s.name)) FROM application_access aa JOIN sites s ON s.id=aa.site_id WHERE aa.provider_id=p.id),'[]') AS applications FROM identity_providers p ORDER BY p.id`)
	}))
	m.HandleFunc("GET /api/identity-providers/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		p, e := readIdentityProvider(r.Context(), a.db, id)
		if e != nil {
			return e
		}
		respond(w, 200, p)
		return nil
	}))
	m.HandleFunc("POST /api/identity-providers", a.wrap(true, a.saveIdentityProvider))
	m.HandleFunc("PUT /api/identity-providers/{id}", a.wrap(true, a.saveIdentityProvider))
	m.HandleFunc("DELETE /api/identity-providers/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, actor identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			var used bool
			if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM application_access WHERE provider_id=$1)", id).Scan(&used); e != nil {
				return e
			}
			if used {
				return apiError{409, "provider is assigned to applications; remove its assignments first"}
			}
			tag, e := tx.Exec(r.Context(), "DELETE FROM identity_providers WHERE id=$1", id)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return apiError{404, "provider not found"}
			}
			return audit(r.Context(), tx, actor.Username, "identity_provider.deleted", strconv.FormatInt(id, 10))
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"deleted": true})
		return nil
	}))
	m.HandleFunc("GET /api/application-access", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, `SELECT s.id AS site_id,s.name,s.hostnames,coalesce(a.revision,0) AS revision,coalesce(a.settings,jsonb_build_object('enabled',false,'provider_id',0,'public_origin','https://'||s.hostnames[1],'allowed_groups','[]'::jsonb,'allow_any_authenticated',false,'session_minutes',30)) AS settings FROM sites s LEFT JOIN application_access a ON a.site_id=s.id ORDER BY s.id`)
	}))
	m.HandleFunc("GET /api/application-access/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		s, e := readApplicationAccess(r.Context(), a.db, id)
		if e != nil {
			return e
		}
		respond(w, 200, s)
		return nil
	}))
	m.HandleFunc("PUT /api/application-access/{id}", a.wrap(true, a.saveApplicationAccess))
	m.HandleFunc("GET /api/application-sessions", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		where := ""
		if raw := r.URL.Query().Get("site_id"); raw != "" {
			id, e := strconv.ParseInt(raw, 10, 64)
			if e != nil || id < 1 {
				return invalid("invalid site_id")
			}
			where = " AND site_id=" + strconv.FormatInt(id, 10)
		}
		return a.list(w, r, "SELECT id,site_id,provider_id,identity,created_at,expires_at FROM application_sessions WHERE expires_at>now()"+where+" ORDER BY created_at DESC LIMIT 200")
	}))
	m.HandleFunc("DELETE /api/application-sessions/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, actor identity) error {
		id := r.PathValue("id")
		if len(id) < 16 || len(id) > 128 {
			return invalid("invalid session ID")
		}
		e := a.change(r.Context(), func(tx pgx.Tx) error {
			if _, e := tx.Exec(r.Context(), "DELETE FROM application_sessions WHERE id=$1", id); e != nil {
				return e
			}
			return audit(r.Context(), tx, actor.Username, "application_session.revoked", id)
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"revoked": true})
		return nil
	}))
	m.HandleFunc("POST /api/application-access/{id}/revoke", a.wrap(true, func(w http.ResponseWriter, r *http.Request, actor identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			if _, e := readApplicationAccess(r.Context(), tx, id); e != nil {
				return e
			}
			if _, e := tx.Exec(r.Context(), "DELETE FROM application_sessions WHERE site_id=$1", id); e != nil {
				return e
			}
			return audit(r.Context(), tx, actor.Username, "application_sessions.revoked", fmt.Sprint(id))
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"revoked": true})
		return nil
	}))
}
