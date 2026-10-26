# Change history

This records shipped behavior rather than proposed features. Container builds use `latest` plus unique build tags/digests; these dated entries are not semantic-version releases.

## 2026-10-26 — Shared mitigation catalogue

- Workspace feeds use a checksummed manifest and one independently versioned JSON file per rule, with CVEs, applicability, compatibility risks and bounded regression cases. Sync every 12 hours or manually; failed updates preserve the last good catalogue.
- Review/search individual rules or packs and apply them to selected policies. Published copies retain provenance and stay pinned until an explicit refresh. Catalogue updates invalidate stale MCP simulations without changing enforcement.
- One-time community subscription includes opt-in Node.js Brotli and PHP multipart delivery-path guards. These are partial mitigations, with documented upload compatibility costs; patch affected runtimes.
- Schema 20 preserves legacy application feeds/imports and existing policy assignments. Removing the default subscription persists across restarts.
- Reviewed documentation now separates completed controls from remaining limitations, including automatic access/audit retention, administrator MFA, resource-scoped authority and online key rotation.

## 2026-10-26 — Alerts and dashboard improvements

### Added

- Configurable alert inbox, scoped trigger rules and asynchronous notification delivery: signed automation/generic webhooks, Slack, Discord, Gotify, ntfy and an optional existing Apprise bridge. PostgreSQL coordinates replicas, encrypted destination settings, cooldowns, retry leases and acknowledgement. MCP exposes investigation/acknowledgement; a configured external receiver wakes the operator’s agent. [Alert setup and guarantees](docs/alerts.md).

### Improved

- Local live traffic flow now uses compact proxy-host pills, stable alphabetical order, name/domain search and paging (12 hosts on wide screens, 6 on narrow screens). Selected-host filtering preserves navigation to other hosts and labels their counts outside the filter; bounded pulses, direct links, disabled states and reduced motion remain supported. [Local map](docs/dashboard.md#local-traffic-flow).

### Operational boundaries

- Additive schema version 19; no destinations or rules are created automatically. Notifications do not change WAF configuration versions. History retains 30 days and approximately 1000 alerts; at-least-once delivery requires receiver deduplication. The current MCP transport remains stateless: users configure their own webhook receiver or polling agent.

## 2026-10-25 — Bot verification and platform hardening

### Added

- Explicit Website/API/SSE proxy-host profiles. API/SSE use JSON gateway denials, omit browser-header mismatch scoring, and block suspicious clients without browser CAPTCHA. All retain policy-configured signatures/body limits. Existing Web defaults are preserved; existing streaming hosts now use machine-client bot handling. [Profiles](docs/body-inspection.md#endpoint-profiles).

- Selective, fully self-hosted image/audio CAPTCHA with explainable suspicion scores, expiring application/client-bound clearance and PostgreSQL-backed multi-replica verification. Existing policies keep it disabled until configured. [Bot protection](docs/bot-protection.md).
- Enforced MCP `simulate_rule_impact` before live rule/policy/host/protection/existing-address mutations. Receipts bind the key, exact candidate and configuration version, expire after two minutes and can be used once. Unknown evidence stays unknown; unconfigured test hosts cannot satisfy assertions. [Agent workflow](docs/agent-access.md#required-simulation-before-live-protection-changes).
- Per-host Web or SSE/streaming profiles and bounded overlapping response inspection. Streams deliver immediately; detections can terminate future output, not retract sent bytes. [Inspection modes](docs/body-inspection.md).
- Optional Redis/Dragonfly rate-state backend for shared flood and bot-frequency budgets, configured in **System** with encrypted write-only credentials and connection testing. Default local mode and the two-container deployment remain available. [Shared counters](docs/shared-rate-state.md).
- Authenticated management Prometheus request/decision counters, inspection histograms, MCP completion counts and process metrics, plus secret-free structured MCP completion events. Read keys can scrape metrics with MCP disabled. [Observability](docs/observability.md).

### Verified and corrected

- Atomic configuration reload preserves admitted HTTP/1.1, HTTP/2 and upgraded connections while new requests and TLS handshakes use the refreshed policy/certificate. Invalid candidates retain the working snapshot. [Architecture](docs/architecture.md#atomic-reload-and-active-connections).
- Native client-IP rules use the resolved trusted-proxy identity. Local idle-bucket cleanup preserves full-refill semantics for large bursts. MCP tool panics and typed-nil SDK results are contained safely.
- Updated `golang.org/x/net` to v0.60.0 for available HTTP/2 advisory fixes. Dependency notices and vulnerability checks cover the distributed build. [Verification](docs/verification.md).
- Real PostgreSQL/Redis/Dragonfly, race/vet, browser/Pebble, container outage/recovery and latency checks passed. The measured small-request CRS baseline was approximately 10,808 requests/sec, 1.471 ms mean and 3.793 ms p99; these are fixture results, not production capacity. [Measurements](docs/benchmarks.md#platform-hardening-verification-2026-10-25).

### Upgrade notes and limits

- Additive schema migrations reach version 18. Existing applications default to Web, an 8192-byte streaming window and local counters; existing policies, assignments, certificates and credentials are preserved. Update all replicas before enabling new shared policy fields.
- Existing MCP enforcement clients must obtain and pass simulation receipts. Import the updated agent skill; a receipt grants no extra authority and does not impose a separate human-review requirement.
- Redis/Dragonfly is optional. Shared enforcing counters fail with 503 on backend failure; there is no automatic fallback to multiplying local budgets.
- Response inspection remains off by default. CAPTCHA does not prove bot identity, and clearance does not bypass other protections. Logging remains best effort; automatic access/audit retention, MFA and online encryption-key rotation are not implemented.

See [upgrade instructions](docs/updating.md), [current limits](docs/limitations.md) and the [limitations review](docs/limitations-review.md).
