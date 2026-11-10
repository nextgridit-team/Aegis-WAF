# Application access

Application access requires an external identity before forwarding traffic to a protected application. It is independent of WAF inspection mode and network bypass rules. Existing applications remain public until access is explicitly enabled.

The two provider types are **OIDC** and **LDAP**. OIDC uses authorization code flow with PKCE, state and nonce; users sign in at their provider. LDAP uses an Aegis login form and a TLS-protected directory connection. Passwords and provider secrets are never returned by management reads or written to access logs. LDAP provides password authentication; use an OIDC provider when MFA is required.

## Management contract

All operations use the ordinary authenticated API and are discoverable through MCP `list_management_operations` and executable with `management_operation`. Configuration reads never return secrets. Writes use optimistic `revision` checks. Provider and application changes invalidate existing sessions.

- `GET /api/identity-providers`: provider inventory, secret-presence flags and application assignments.
- `GET /api/identity-providers/presets`: OIDC, Authentik, Entra ID, Google, OpenLDAP and Active Directory setup templates.
- `POST /api/identity-providers`: create a provider.
- `PUT /api/identity-providers/{id}`: update settings and optionally replace its secret.
- `DELETE /api/identity-providers/{id}`: remove an unassigned provider.
- `POST /api/identity-providers/{id}/test`: bounded discovery/TLS or directory bind diagnostics.
- `POST /api/identity-providers/{id}/groups`: bounded LDAP group lookup; OIDC groups/roles are supplied through configured claims.
- `GET /api/application-access`: settings and setup status for each application.
- `PUT /api/application-access/{id}`: assign a provider and group restrictions to an application.
- `GET /api/application-sessions`: active sessions, optionally filtered by `site_id`.
- `DELETE /api/application-sessions/{id}`: revoke one session.
- `POST /api/application-access/{id}/revoke`: revoke all sessions for an application.

Provider configuration is separate from application authorization. A provider has `name`, `type`, `enabled`, `oidc` or `ldap` settings, optional `ca_pem`, a write-only `secret` and `revision` on update. Omitted/empty secrets preserve the stored value. Changing credential destinations requires supplying the secret again. Provider secrets are encrypted with the deployment key.

Application settings include `enabled`, `provider_id`, `public_origin`, `allowed_groups`, `allow_any_authenticated`, `session_minutes`, and `revision`. An enabled restriction must explicitly select groups or allow all authenticated identities. `public_origin` must be HTTPS and match an application hostname. Group values are exact OIDC claim values or LDAP distinguished names. Custom OIDC group claims can use `roles` for Entra application roles. Google login does not supply Workspace group membership; use a group-capable broker or explicitly allow authenticated identities from a configured provider.

## Enforcement and operations

Sessions are host- and application-bound, stored as token hashes in PostgreSQL, and validated against current provider/access revisions on each protected request. Cookies are Secure, HttpOnly, SameSite=Lax and host-only. Database failure denies protected requests. Provider failure never grants access. Group membership is evaluated at sign-in and remains valid only for the configured session lifetime (also capped by OIDC token expiry); revoke sessions to require earlier reevaluation. Revocation applies to new requests; already authorized requests and open WebSocket/streaming connections may finish. No user password is stored.

OIDC callback URLs are the configured application origin plus `/__aegis/auth/callback`. LDAP login and logout use the same reserved `/__aegis/auth/` namespace. Browser navigation can redirect to login; API requests receive an authentication-required response. Login routes have bounded bodies, concurrency and attempt limits and bypass traffic-body capture. Application session cookies are removed before forwarding. Incoming `X-Aegis-Identity-*` headers are stripped; authentication does not automatically log a user into an upstream application's own account system.

Only expose upstream applications through Aegis. TLS verification is mandatory for providers; an internal CA can be supplied. LDAP accepts `ldaps://` or mandatory StartTLS on `ldap://`. Private directory and identity-provider hosts are supported through explicitly configured destinations; discovery endpoints cannot silently send client secrets to a different origin.

## Callback restrictions

The callback allowlist is derived from the saved application assignment: its exact HTTPS `public_origin`, fixed `/__aegis/auth/callback` path, and assigned enabled OIDC provider. LDAP and applications without enabled access have no OIDC callback. Provider selection never comes from callback parameters. A callback on HTTP, another hostname/port, or an encoded variation of the path is rejected instead of redirected. Unknown authentication paths return 404 and never reach the upstream.

Callbacks come through the visitor's browser, not an identity-provider server connection. Provider IP, Origin or Referer allowlists cannot authenticate that browser redirect. Aegis instead verifies the browser cookie and expiring, one-time state bound to the application, provider and both configuration revisions, followed by PKCE, nonce and signed ID-token validation. Malformed, duplicated, oversized or conflicting callback parameters are rejected before provider network work; only GET callbacks without request bodies are supported. Normal provider extension parameters are bounded and ignored.

If a callback includes `iss`, it must exactly match the assigned issuer. If discovery advertised `authorization_response_iss_parameter_supported`, that requirement is saved with the initiating login flow and a callback missing `iss` is rejected before token exchange. Providers without that feature retain the same provider/state/token binding. See [OAuth authorization-server issuer identification (RFC 9207)](https://www.rfc-editor.org/rfc/rfc9207.html). Do not add a broad WAF bypass for these paths: their dedicated handlers validate authentication and exclude credentials from traffic capture.

## Setup from the dashboard

1. Open **Application access** and choose **Add identity provider**. Select a template, enter the issuer/client registration or directory bind settings, and save. A connection test runs automatically; its result distinguishes CA trust, hostname, network and service-bind failures.
2. Choose **Configure access** for an application. Select the provider and canonical HTTPS origin. For OIDC, copy the displayed redirect URI to the provider's web application registration. Configure the ID token to carry the selected group or role claim. For LDAP, browse groups or enter complete DNs.
3. Select the allowed groups/roles and session lifetime, then enable **Require sign-in**. The application must already be reachable over HTTPS. Test with both a permitted user and an unassigned user. The connection diagnostic alone does not prove group authorization.
4. Review **Active sessions**. Revoke one session or all application sessions when access needs to be reevaluated. Disabling a provider denies access to applications that still require it; turn off the application's requirement explicitly to make it public.

For LDAP, the default membership search covers direct groups. Nested membership is directory-specific and must be configured deliberately in `group_filter` (for example an appropriate Active Directory matching-rule filter). OIDC requests only configured scopes; some providers require adding `groups` to scopes before issuing that claim. Entra app-role values are easier to assign and evaluate than large group lists. Provider sessions and MFA policies remain managed by the identity provider.

## Agent setup without dashboard interaction

Use Read, Configuration and Enforce permissions on an existing source-restricted MCP key. Discover presets and current application settings, create the provider with approved credentials, run its test, then discover LDAP group DNs or obtain exact OIDC role/claim values. The complete input shapes are in `get_management_contract` and [the API reference](management-api.md#application-access-oidc-and-ldap).

For application 123, provider 7, and an existing `finance.example.com` host, a simulation call can use:

```json
{
  "method": "PUT",
  "path": "/api/application-access/123",
  "input": {"revision":0,"enabled":true,"provider_id":7,"public_origin":"https://finance.example.com","allowed_groups":["Finance.Reader"],"allow_any_authenticated":false,"session_minutes":30},
  "test_payloads": [
    {"host":"finance.example.com","path":"/","expected":"block"},
    {"host":"finance.example.com","path":"/","identity":{"subject":"test-outsider","groups":["Other.Role"]},"expected":"block"},
    {"host":"finance.example.com","path":"/","identity":{"subject":"test-reader","groups":["Finance.Reader"]},"expected":"allow"}
  ]
}
```

Submit the identical method/path/input with the returned `simulation_id` through `management_operation`, then read back the assignment and wait for every replica to load the new configuration (normally within two seconds). Initial enablement becomes effective as those snapshots refresh. Simulation makes no provider or upstream requests; use a real sign-in to confirm the provider registration and emitted claims. Application authentication cannot mint administrator sessions or MCP keys.

## Upgrade behavior

Update every serving replica before enabling application access; older binaries do not enforce it. Existing applications remain public. The schema upgrade adds provider, access, session and temporary-flow tables; schema 27 also pins issuer-response requirements to each flow. This release increments the sealed snapshot format because older snapshots cannot represent a login requirement: the first startup on the new version needs PostgreSQL to build a fresh snapshot. Later database outages continue serving public applications from valid snapshots while protected applications deny access. Avoid rolling back to a binary that predates application authentication while any application requires it.
