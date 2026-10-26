# Permissions and connection

An administrator enables **Agent access**, creates a named expiring key, and chooses allowed IP objects/groups. Configure the agent's MCP client with the native management HTTPS URL ending in `/mcp` and `Authorization: Bearer <key>` through the client's secret store. Custom bearer credentials are required; OAuth discovery/browser consent is not implemented. Do not place a real key in this file, tool arguments, example URLs, chat output or a committed MCP config.

| Scope                | Authority                                                                                                                                                 |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Read                 | Always available: application/policy/rule/certificate metadata, request logs, status and audit/history                                                    |
| Evidence             | Retained samples, details containing samples, offline replay                                                                                              |
| Draft                | Create disabled custom rule proposals                                                                                                                     |
| Enforce              | Modify/activate/disable/rollback rules, policies, signatures and feeds                                                                                    |
| Configuration        | Applications, routing/headers/proxy trust/exemptions, address objects/groups, Geo, shared rate-state and traffic settings; can affect security boundaries |
| Certificates         | Upload/replace/delete certs, DNS credentials, issuance/jobs and directory lookup; no stored secret readback                                               |
| Agent administration | Read existing key metadata, revoke keys, enable/disable endpoint; cannot create keys/accounts                                                             |

Select only the scopes required for the operator's playbook. Scopes apply to the entire workspace, not individual applications. Exact permitted routes come from `list_management_operations`; `get_management_contract` describes their bodies. Convenience tools remain available alongside the general management tool. Full automation can use all scopes, but still cannot create accounts, sessions or new keys.

Connecting IP restrictions use the socket peer and ignore forwarded headers. Behind NAT/proxies this can be the shared egress address; do not modify a proxy host's trust list to try to bypass MCP source checks. PostgreSQL authorizes every MCP HTTP request. Revocation, disabled access or source edits affect the next request; already authorized operations may complete within the request deadline. Database loss denies agent access while existing proxy snapshots continue serving.

Handle failures:

- 401: key absent, expired or revoked. Report the issue; do not repeat the credential or create replacements.
- 403: source, Origin, transport or scope restriction. Request an administrator's change if authorized; never spoof headers to evade it.
- 404: endpoint disabled or resource unavailable. Check discovery/current settings where possible.
- 409: concurrent edit or a referenced resource. Reload and reconcile, or remove intended references before deletion.
- 428: simulation is missing, stale, expired, used or mismatched. Re-simulate the exact operation; never bypass the receipt gate.
- 429/busy: back off and retry within the operator's budget; do not start parallel retry storms.
- 503/database errors: retain the intended change, report failure accurately and retry later if authorized. Do not report a successful mutation without readback.

MCP operation errors are also returned as tool results with `isError=true`; read the error rather than treating a successful transport response as a successful operation. The transport is stateless: a load balancer can route requests to any replica. It permits eight concurrent MCP HTTP requests per replica, with a 30-second deadline; long tasks such as queued Geo sync need later status polling.

Read keys can also authenticate management HTTPS `/metrics` scrapes even when MCP itself is disabled. Source restrictions, expiry and revocation still apply. Metrics contain no request payloads or client-IP labels.
