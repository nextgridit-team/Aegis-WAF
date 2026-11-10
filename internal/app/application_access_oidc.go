package app

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *App) startOIDC(w http.ResponseWriter, r *http.Request, access applicationAccess, p storedIdentityProvider) error {
	if e := a.applicationLoginLimit(r, p.ID, ""); e != nil {
		return e
	}
	release, e := a.identityWork(r)
	if e != nil {
		return e
	}
	defer release()
	_, config, _, e := a.oidcProvider(r.Context(), p, access.Settings.PublicOrigin)
	if e != nil {
		return e
	}
	state, browser, nonce, verifier := token(), token(), token(), oauth2.GenerateVerifier()
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(700041)"); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM application_auth_flows WHERE expires_at<=now()"); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM application_auth_flows").Scan(&count); e != nil {
		return e
	}
	if count >= 1024 {
		return apiError{503, "too many sign-in attempts; retry shortly"}
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO application_auth_flows(state_hash,browser_hash,site_id,provider_id,access_revision,provider_revision,origin,return_path,nonce,verifier,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+interval '10 minutes')`, hash(state), hash(browser), access.SiteID, p.ID, access.Revision, p.Revision, access.Settings.PublicOrigin, safeApplicationReturn(r.URL.Query().Get("return")), nonce, verifier); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	applicationCookie(w, applicationFlowCookie, browser, 600)
	http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
	return nil
}

func (a *App) finishOIDC(w http.ResponseWriter, r *http.Request, access applicationAccess, p storedIdentityProvider) error {
	if e := a.applicationLoginLimit(r, p.ID, ""); e != nil {
		return e
	}
	release, e := a.identityWork(r)
	if e != nil {
		return e
	}
	defer release()
	query := r.URL.Query()
	cookie, e := r.Cookie(applicationFlowCookie)
	state, code := query.Get("state"), query.Get("code")
	if e != nil || len(cookie.Value) > 128 || state == "" || len(state) > 128 || len(code) > 8192 || len(r.URL.RawQuery) > 16384 {
		return apiError{400, "invalid sign-in callback; start again"}
	}
	var nonce, verifier, returnTo string
	e = a.db.QueryRow(r.Context(), `DELETE FROM application_auth_flows WHERE state_hash=$1 AND browser_hash=$2 AND site_id=$3 AND provider_id=$4 AND access_revision=$5 AND provider_revision=$6 AND origin=$7 AND expires_at>now() RETURNING nonce,verifier,return_path`, hash(state), hash(cookie.Value), access.SiteID, p.ID, access.Revision, p.Revision, access.Settings.PublicOrigin).Scan(&nonce, &verifier, &returnTo)
	if e != nil {
		return apiError{400, "sign-in request expired or already used; start again"}
	}
	applicationCookie(w, applicationFlowCookie, "", -1)
	if query.Get("error") != "" || code == "" {
		return apiError{401, "identity provider did not complete sign-in"}
	}
	provider, config, ctx, e := a.oidcProvider(r.Context(), p, access.Settings.PublicOrigin)
	if e != nil {
		return e
	}
	tokens, e := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if e != nil {
		return apiError{401, "identity provider rejected the sign-in code"}
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok || len(raw) > 128<<10 {
		return apiError{401, "identity provider returned no valid identity token"}
	}
	verified, e := provider.Verifier(&oidc.Config{ClientID: config.ClientID}).Verify(ctx, raw)
	if e != nil || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(nonce)) != 1 || verified.IssuedAt.After(time.Now().Add(time.Minute)) {
		return apiError{401, "identity token verification failed"}
	}
	var claims map[string]json.RawMessage
	if e = verified.Claims(&claims); e != nil {
		return apiError{401, "invalid identity claims"}
	}
	claimString := func(key string) string { var value string; _ = json.Unmarshal(claims[key], &value); return value }
	// A token with several audiences must explicitly identify this client.
	authorizedParty := claimString("azp")
	if (len(verified.Audience) > 1 && authorizedParty == "") || (authorizedParty != "" && authorizedParty != config.ClientID) {
		return apiError{401, "identity token client mismatch"}
	}
	identity := applicationIdentity{Subject: verified.Subject, Username: claimString("preferred_username"), Email: claimString("email"), Groups: []string{}}
	if identity.Username == "" {
		identity.Username = claimString("name")
	}
	if identity.Username == "" {
		identity.Username = identity.Subject
	}
	if groupClaim := claims[p.Settings.OIDC.GroupsClaim]; len(groupClaim) > 0 && string(groupClaim) != "null" {
		if e = json.Unmarshal(groupClaim, &identity.Groups); e != nil {
			return apiError{403, "configured group claim must be an array of strings"}
		}
	}
	for _, group := range identity.Groups {
		if strings.TrimSpace(group) == "" {
			return apiError{403, "invalid group claim"}
		}
	}
	session, e := a.createApplicationSession(ctx, access, p, identity, verified.Expiry)
	if e != nil {
		return e
	}
	applicationCookie(w, applicationSessionCookie, session, access.Settings.SessionMinutes*60)
	http.Redirect(w, r, access.Settings.PublicOrigin+safeApplicationReturn(returnTo), http.StatusSeeOther)
	return nil
}
