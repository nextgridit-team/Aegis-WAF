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
- `GET /access-logs/{id}`: request metadata, recorded policy/custom-rule definitions, matched managed-signature metadata and only unexpired retained evidence. See [request investigation](request-investigation.md).
- Rule lifecycle, JSON schema, traffic settings, evidence and offline replay: see the [rules API](rules.md#management-api).

For mutations, send `Content-Type: application/json`, `X-Requested-With: aegis-waf`, and the current `X-CSRF-Token` (except setup/login, which have no session yet). Errors return JSON with an `error` field. Database failures return 503 without claiming success; invalid input returns 400; conflicts return 409. A connection loss exactly at commit can leave an ambiguous result; refresh state before repeating a create operation.

## Additional resources

- [Policies and application assignments](policies.md).
- [Managed signature sets](managed-signatures.md): `GET /api/signature-sets`, `GET /api/signature-sets/catalogue`, `GET /api/signature-sets/{id}/rules` for static inventory, and `POST /api/signature-sets` with the catalogue set ID.
- [Rule feeds](rule-feeds.md), [dashboard and protection](dashboard.md), [headers and CIDRs](headers-and-cidrs.md), and [AI provider configuration](ai-provider.md).

This is a starting reference, not a generated complete API schema. Site writes also support the documented protection/header settings. Read each feature's API and limits before automating it.

## Address objects, Geo and agents

- `GET/POST /address-objects`, `PUT/DELETE /address-objects/{id}`: `name`, `description`, one `value` (IP, CIDR or IPv4 dotted subnet). Groups use `GET/POST /address-groups`, `PUT/DELETE /address-groups/{id}` with `name`, `description`, `object_ids`. Selection fields are `{object_ids:[],group_ids:[]}`. Hosts accept `trusted_addresses`, `flood_exempt_addresses`, `bot_exempt_addresses` inside protection; policy `network_access` accepts `block_addresses`, `allow_addresses` alongside literal CIDRs. Referenced deletion/conflicting edits return 409. See [address semantics](address-objects.md).
- `POST /geolocation/sync`: `{detail:"country"|"city",auto_sync:true|false,accept_license:true}` returns 202 queued; `GET /geolocation/status` returns data timestamps, job/error/sync status. Existing `POST /geolocation/update` is the synchronous Country-only compatibility endpoint.
- `GET /dashboard/regions?country=US&minutes=15&site_id=1&region=WA`: counts plus up to 20 recent requests. Site/region optional; minutes 5/15/60; `region=unknown` selects missing regions. Logs include `region_code`, `region_name`, `network_access`.
- `GET/PUT /agent-access`: `{enabled:false|true}`. `GET /agent-keys` returns metadata only. `POST /agent-keys`: `{name,scopes:["read"],allowed_addresses:{object_ids:[],group_ids:[]},expires_in_days:90}` returns 201 with a one-time `api_key`. `DELETE /agent-keys/{id}` revokes. Creation requires nonempty valid source selection. Dashboard APIs require administrator session and CSRF.
- `/mcp` on management uses separate bearer authentication, source checks and tool permissions, not dashboard sessions. See [transport, tools and limits](agent-access.md).

Managed policy signatures also accept `scoped_exclusions:[{rule_ids:[942100],path_prefix:"/search",parameters:["q"],client_cidrs:["192.168.1.0/24"]}]`. TrafficSettings accepts `security_events_disabled` and `security_samples`, both default false. See [scope semantics and telemetry privacy](security-tuning.md).

Agent scopes: `read` (always included), `evidence`, `draft`, `enforce`, `configuration`, `certificates`, `agent_admin`. Broad management uses `list_management_operations`, `get_management_contract` and `management_operation` with `{method,path,input}`. Account/session/bootstrap operations and new MCP-key creation are hard-denied regardless of scopes. Existing-key revocation requires `agent_admin`. Configuration changes can affect routing/trust/protection boundaries.

`GET /agent-access/skill` downloads the authenticated `aegis-waf.zip` portable skill bundle (binary ZIP, not JSON). MCP `get_agent_skill` returns the same files as structured documentation, separately from general management operations. Import behavior depends on the agent client.
