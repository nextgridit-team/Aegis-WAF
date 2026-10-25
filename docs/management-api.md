# Management API

All endpoint paths below are relative to `/api` on the management listener. There are no bearer-token or private-key export APIs. Use the dashboard for interactive management, or a cookie jar for automation:

- `GET /setup`, `POST /setup` (`username`, `password`, `secret`): one-time administrator bootstrap.
- `POST /login` (`username`, `password`): returns username and CSRF token and sets the session cookie. `GET /me` returns the current CSRF token. `POST /logout` revokes the session.
- `GET /status`: this replica's loaded version, database refresh health, propagation interval, and access log drop count.
- `GET /sites`, `POST /sites`, `PUT /sites/{id}`, `DELETE /sites/{id}`: site management. Write fields: `name`, `hostnames`, `upstream`, nullable `certificate_id`, `redirect_https`, `preserve_host`, `enabled`. Send all fields on PUT. POST also accepts optional `initial_policy_id` for atomic default-policy assignment; PUT rejects that create-only field when nonzero.
- `GET /certificates`: metadata, validity, and assignments. `POST /certificates`, `PUT /certificates/{id}`: `name`, `chain_pem`, `private_key_pem`. PUT replaces an uploaded certificate only. `DELETE /certificates/{id}` requires no assignments or active jobs.
- `GET /acme/directory?url=staging|production|<encoded HTTPS URL>`: discover CA terms.
- `GET /acme/accounts`, `POST /acme/accounts`: registration fields `directory` (`staging`, `production`, or HTTPS URL), `email`, `accept_terms: true`.
- `POST /acme/certificates`: `name`, `domains`, `account_id`, optional `challenge_type` (`http-01` by default or `dns-01`), and `dns_credential_id` for DNS-01; returns 202 after queuing issuance. Attach it to sites after issuance succeeds.
- `GET/POST /dns/credentials`, `PUT/DELETE /dns/credentials/{id}`: encrypted Cloudflare token management; read APIs return metadata only.
- `GET /acme/jobs`, `POST /acme/jobs/{id}/retry`: newest 100 jobs with order history; retry only accepts jobs in `retry` state.
- `GET /audit`, `GET /access-logs`: latest 200 records.
- Rule lifecycle, JSON schema, traffic settings, evidence and offline replay: see the [rules API](rules.md#management-api).

For mutations, send `Content-Type: application/json`, `X-Requested-With: aegis-waf`, and the current `X-CSRF-Token` (except setup/login, which have no session yet). Errors return JSON with an `error` field. Database failures return 503 without claiming success; invalid input returns 400; conflicts return 409. A connection loss exactly at commit can leave an ambiguous result; refresh state before repeating a create operation.

## Additional resources

- [Policies and application assignments](policies.md).
- [Managed signature sets](managed-signatures.md): `GET /api/signature-sets`, `GET /api/signature-sets/catalogue`, `GET /api/signature-sets/{id}/rules` for static inventory, and `POST /api/signature-sets` with the catalogue set ID.
- [Rule feeds](rule-feeds.md), [dashboard and protection](dashboard.md), [headers and CIDRs](headers-and-cidrs.md), and [AI provider configuration](ai-provider.md).

This is a starting reference, not a generated complete API schema. Site writes also support the documented protection/header settings. Read each feature's API and limits before automating it.
