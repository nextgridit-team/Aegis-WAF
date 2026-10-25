# External agents through MCP

Aegis exposes an optional **Streamable HTTP MCP endpoint at `/mcp` on the management listener**. There is no local model, inference worker, AI request-path dependency, or extra container. Choose your own agent, model endpoint, instructions, schedules and approval process.

## Setup

1. In **Address objects**, create one object for the agent's source IP/CIDR/subnet, optionally add it to a group. When NAT or a management proxy is involved, use the address that actually connects to Aegis. Forwarded headers are ignored for agent authorization.
2. Open **Agent access**, enable the endpoint and save. This is independent of public proxy hosts.
3. Create a named API key, select allowed source objects/groups, permissions and expiry (default 90 days; 1–365 days). Save the key in your agent's secret store: it is displayed once. PostgreSQL retains a SHA-256 hash of the random 256-bit credential, not the usable key.
4. Configure your MCP client with `https://your-management-host:9090/mcp` and an `Authorization: Bearer <API key>` header. Use native management TLS for remote access. Loopback HTTP is supported for local development only.

The client must support administrator-provisioned bearer credentials. OAuth discovery, dynamic client registration and browser consent are not implemented; clients requiring those flows cannot connect directly. The official Go SDK implements protocol negotiation and stateless transport; no sticky load-balancer session is needed.

## Import or adapt the bundled skill

Select **Download agent skill** on Agent access to download `aegis-waf.zip` using your dashboard session. The archive contains `aegis-waf/SKILL.md`, permissions/connection notes, playbook examples and the MIT license. Extract/import it using your agent's skill installation flow. Client-specific import support varies; MCP itself does not automatically install skills.

After connecting, an agent can call `get_agent_skill` to read the same files and adapt them to its own instructions/playbook. Source files are available in [skills/aegis-waf](../skills/aegis-waf/SKILL.md). The package follows the [Agent Skills format](https://agentskills.io/specification); it contains documentation only, no credentials or executable scripts.

Included workflows cover request investigation, false-positive tuning, disabled rule proposals and replay, application/certificate setup, feeds/Geo/address objects, revision-aware rollback and operator-defined autonomous limits. They honor standing authorization; importing the skill neither grants permissions nor requires a particular model/provider. It is a starting point for your own workflow, not a built-in inference service.

## Permissions and tools

| Permission | Available tools | Effect |
| --- | --- | --- |
| Read (always included) | `get_dashboard`, `list_applications`, `list_policies`, `list_rules`, `get_rule_schema`, `list_signature_sets`, `list_access_logs` | Workspace metadata, aggregates and latest 200 request records; no retained request samples |
| Evidence | `get_request_details`, `list_evidence`, `replay_rule` | Retained request facts and offline custom-rule replay; missing/expired facts remain unavailable |
| Draft | `propose_rule` | Creates a disabled rule; does not update or activate existing rules |
| Enforce | Rule, signature, feed and policy mutations through `management_operation`, plus convenience tools | Can change live protections, assignments, history and rollback |
| Configuration | Application, proxy-header/trust/exemption, address-object/group, Geo, traffic and compatibility provider settings | Can change routing and security boundaries and enable evidence collection |
| Certificates | Certificate upload/replacement/deletion, DNS credentials, directory lookup, issuance and job retry | Handles certificate operations; stored keys/tokens are never returned |
| Agent administration | Read agent/key metadata, revoke existing keys, enable/disable agent endpoint | Cannot create new keys or accounts, even with all scopes |

Permissions cover the whole workspace; per-application agent roles are not implemented. Stored private keys/tokens, administrator/bootstrap/session operations, new accounts (including ACME registration), and new MCP-key creation remain unavailable. Uploading certificates or supplying new DNS credentials is permitted by the certificate scope; normal APIs never read stored secrets back.

`list_management_operations` discovers every permitted management route; `get_management_contract` supplies payload documentation; `management_operation` accepts `{method,path,input}` and dispatches only to an explicitly registered management route. This covers every other current management operation, including history, rollback, application creation/deletion, signature inventory, feed sync/import and settings. Paths are relative `/api/...` paths, with optional query filters; arbitrary URLs, SQL, shell execution and recursion into MCP are unavailable. API route additions require explicit catalog review before exposure.

For example, a Configuration key can call `management_operation` with `method:"POST"`, `path:"/api/address-objects"`, `input:{name:"Office",value:"192.168.10.0/24"}`. An Enforce key can update policies or request rollback using the normal revision checks. Convenience investigation/draft/replay tools remain available.

Scopes grant authority to whole management domains, not isolated safety guarantees: Configuration can change routing, proxy trust, exemptions and traffic collection; Enforce can remove protections. Review each key's combined authority.

Typical workflow: read rule schema and metadata → inspect approved retained evidence → draft a typed rule → replay against attack **and legitimate** samples → review unknowns and false positives → activate using an operator or separately authorized enforcement key. Aegis validates normal rule/policy limits and preserves transactional audits; it does not enforce your external agent's human-approval workflow. Granting Enforce allows autonomous changes.

Tool calls use `id` for an existing resource and `input` for the corresponding management API payload. `propose_rule` takes a RuleSpec; `replay_rule` takes `{rule,event_ids}`; `activate_rule` takes `{action,ttl_seconds}`; `save_policy` requires the current policy revision and complete intended assignments. Consult [management API](management-api.md). SDK tool descriptions expose these contracts and `get_rule_schema` supplies the custom rule schema.

## Security and operations

- Disabled by default. Keys have independent names, source restrictions, permissions, expirations and revocation. Keys are never accepted from query parameters or dashboard cookies.
- Authorization and address-object resolution use PostgreSQL on **every MCP HTTP request**. Revocation, disable and source changes therefore take effect on the next request across replicas. Authorized in-flight calls may finish (30-second request deadline). Database failure denies agent access while existing proxy snapshots keep serving.
- Management source identity uses the socket peer, not host-specific trusted-proxy settings. TLS terminators/NAT need a restricted connecting address and independent controls on their exposed side. Native HTTPS is required for non-loopback connections.
- Origins, when present, must match the management HTTPS origin. No cross-origin browser access is enabled. Request bodies are capped at 2 MiB; eight concurrent MCP requests per replica are admitted, then HTTP 429 is returned.
- Data/convenience calls record `agent.tool_called`; management operations record `agent.management_called` with key ID and the route template. Discovery and contract tools return static metadata without an audit entry. Mutations also use existing operation-specific audit events. Arguments, bearer credentials and request sample values are not placed in audit events. A failed audit write prevents tool execution.
- Request content is attacker-controlled, including text that resembles agent instructions. Treat tool results as data; do not let captured traffic expand permissions or approve changes. Evidence may contain personal data despite redaction. The agent operator controls where exported data goes.

The prior provider connection API remains for compatibility, but its configuration does not run inference and is no longer the dashboard's AI integration. Existing saved provider credentials are retained; upgrades do not delete them.
