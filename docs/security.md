# Security model and deployment boundaries

Aegis combines request protection and a management plane. The controls below describe the implementation; they are not a certification or a guarantee that every attack will be blocked. Review the [current limits](limitations.md) and tune policies for each application.

## Separate administration from application traffic

The dashboard, management API and optional MCP endpoint use a listener separate from protected HTTP/HTTPS traffic. Compose publishes management only on loopback by default and does not publish PostgreSQL. Use [HTTPS management](deployment.md#remote-https-management) for remote browser access and restrict who can reach it.

First-run setup requires a generated bootstrap secret; no default administrator is shipped. Passwords use bcrypt hashing. Sessions are server-side in PostgreSQL, with hashed session tokens, HttpOnly/SameSite cookies, Secure cookies for remote management and CSRF checks on state-changing browser requests. Security-relevant administrative mutations use transactional audit records. MFA, password recovery and granular administrator roles are not implemented.

## Protect stored secrets

Certificate private keys, ACME account keys and saved provider credentials are encrypted before database writes using AES-256-GCM. The external encryption key is not stored in PostgreSQL. Normal read APIs do not return stored secrets. Public certificate chains, configuration, access logs and audit data are not encrypted by this application layer.

See [certificate storage and lifecycle](certificates.md) and [encryption at rest](encryption-at-rest.md). Operators remain responsible for host/storage/backup protection and retaining the external key for recovery.

## Inspect and control requests within explicit limits

Coraza runs OWASP CRS request signatures in the application. Policies select Observe/Block behavior, signature exclusions, custom rule groups, CIDR/Geo decisions and optional bot/flood controls. The included baseline is assigned explicitly; it does not silently protect every application. Body inspection is bounded, and oversize/busy behavior depends on mode.

Forwarded client-IP headers are accepted only through configured trusted proxies. Address objects carry no implicit trust or bypass: the selected host/policy determines their use. Local-location labels and map filters do not change enforcement. See [policies](policies.md), [managed signatures](managed-signatures.md), [inspection bounds](security-tuning.md) and [client identity](headers-and-cidrs.md).

CRS response inspection is opt-in. Web responses can be withheld for bounded inspection; SSE/streaming profiles inspect overlapping windows after delivery and can terminate future output. WebSocket frames, binary gRPC and unsupported content types are not body-inspected. Bot signals can be spoofed. Local flood budgets are per replica; optional Redis/Dragonfly counters coordinate them across replicas and enforcing controls return 503 on shared-state failure. Selective self-hosted CAPTCHA grants only bounded bot-challenge clearance; it never bypasses the other protection components. Behavioral learning and network-layer DDoS defenses are not implemented. See [bot verification](bot-protection.md).

## Keep evidence collection deliberate

Metadata access logs are separate from opt-in request-content evidence. Evidence has allowlists, size/sampling limits, redaction and expiry. Stdout security events use a [versioned JSON contract](logging.md#security-event-schema-and-collection); payload context defaults to null. Forwarding or response enforcement completes before the bounded asynchronous logging work. Queue saturation or outages can lose records.

Client IPs and retained facts can be personal data. Redaction is best effort. Exported stdout/agent data follows the destination's retention and residency controls, not PostgreSQL evidence expiry. See [evidence privacy](evidence-privacy.md) and [logging](logging.md).

## Scope external agents explicitly

MCP is disabled by default. When enabled, named expiring keys have permissions and source-IP object/group restrictions. PostgreSQL stores key hashes and authorizes each MCP HTTP request; database failure denies agent access. Account creation and new MCP-key creation are excluded. An enforcement-capable key can change live protections; Aegis does not impose your agent's approval process.

The endpoint lets you bring an agent and model. Aegis does not run model inference, behavioral learning or a built-in AI investigation workflow. See [agent setup and permission boundaries](agent-access.md).

MCP live-protection changes additionally require a fresh exact-candidate simulation receipt. This enforced check preserves unknown evidence and scoped authority; it is not proof that traffic is legitimate. Management-only Prometheus metrics use sessions or source-restricted read keys. See [simulation](agent-access.md#required-simulation-before-live-protection-changes) and [observability](observability.md).

## Harden the deployment around the application

The supplied app container runs as non-root, supports a platform-assigned UID, uses a read-only root and explicit temporary directory, drops capabilities and requires no Docker socket. Upstream HTTPS certificate verification is enabled. The supplied app-to-PostgreSQL Docker connection is not TLS-encrypted; use verified TLS for remote PostgreSQL.

Keep management private, patch the host and database, back up PostgreSQL and the external key, and plan log retention. Existing replicas retain their loaded configuration during database loss; default cold starts need PostgreSQL. See [deployment](deployment.md), [architecture](architecture.md), [optional sealed recovery snapshots](snapshot-cache.md) and [verification evidence](verification.md).
