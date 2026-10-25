# Capabilities and current limits

Aegis is under active development. Request protection and the optional MCP agent endpoint are implemented; Aegis runs no AI traffic analysis itself.

- **Flood budgets are replica-local.** More replicas increase the effective aggregate allowance; budgets reset on process restart. Cluster-wide rate coordination is not implemented.
- **CRS inspects requests only.** Response-body inspection is disabled. In Block mode, requests over the policy body limit are rejected with 413; Observe forwards them with incomplete-inspection metadata. New custom policies default to 64 KiB; the included baseline uses 1 MiB. Configurable range: 4 KiB–1 MiB. Review upload-heavy applications before enforcing. [Managed signature behavior](managed-signatures.md).
- **Bot detection is basic and spoofable.** There is no CAPTCHA, browser challenge, verified-bot identity, behavioral learning or network-layer DDoS protection.
- **Agents are external and opt-in.** MCP provides scoped access for your agent; Aegis runs no inference or built-in AI workflow. Grant live enforcement separately from read/evidence/draft access. CRS inbound anomaly scoring is independent. [Agent setup](agent-access.md).
- **Database outages have defined limits.** Running replicas retain their last loaded routes, certificates and policies; sign-in, administrative changes and HTTP-01 lookup still require PostgreSQL. A default replica starting during an outage remains unready. [Failure and recovery behavior](deployment.md#health-and-database-outages).
- **Logs are best effort.** Forwarding/enforcement precede queued log writes. Queue saturation, outages or process crashes can lose records. Access/audit retention is manual; sampled evidence has its own automatic expiry. [Logging](logging.md) · [Privacy](evidence-privacy.md).
- **Encryption covers secret values.** Private keys and saved credentials use AES-256-GCM with an external key. Public certificate chains, configuration and logs are not encrypted by that application layer. Online key rotation, MFA, password recovery and granular administrator roles are not implemented. [Encryption details](encryption-at-rest.md).

See [measured performance and comparison limits](proxy-comparison.md). Those small-workload results do not establish production capacity or security parity with other WAFs.

See the [documentation index](README.md) for deployment and tuning guides.
