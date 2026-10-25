# AI provider connection

Open **AI backend**, enter an OpenAI-compatible API base URL (usually ending `/v1`), and optionally enter an API key. Select **Check connection & load models**, choose a returned text/chat model and save. Keyless local providers are supported. Changes are rechecked before saving; failed checks preserve the saved configuration. Changing endpoints cannot forward a saved key unless the canonical endpoint is unchanged; supply a replacement key or explicitly choose No API key.

Discovery calls `GET <base>/models`, using server-side Bearer authentication when configured. It verifies TLS, bounds response size/time/model count, and does not follow redirects or use environment HTTP proxies. Public endpoints require HTTPS; private/loopback providers can use HTTP. Link-local and metadata endpoints are rejected. Read APIs never return saved credentials; keys are encrypted with AES-256-GCM outside PostgreSQL. The provider configuration is persisted in PostgreSQL with revision checks and audit events.

Model discovery establishes access to the model list. It does not test inference capability: lists may include embedding/audio models. No generation call, traffic submission, automatic rule creation or background traffic review is currently enabled.

[Official OpenAI model-list reference](https://developers.openai.com/api/reference/resources/models/methods/list).

## Proposed next stage: scoring and background review

Keep deterministic rules and rate limits on the synchronous request path. Assign bounded weights to explainable signals and deny at a policy-defined threshold. High-confidence signatures may directly deny; weaker independent signals can accumulate. Avoid counting correlated rules repeatedly. If sender/endpoint risk persists between requests, use a bounded expiring cache and document replica-local behavior. A reputation store must never introduce a database or model dependency for each request.

Run periodic, PostgreSQL-coordinated review jobs per application and a configurable lookback window. Begin with aggregates by endpoint and resolved sender, status mix, rates and existing rule matches; use opt-in redacted samples only when needed. Limit rows, tokens, cost, concurrency and execution time. Treat all traffic fields as untrusted input, including text that attempts to instruct the model.

The model should propose typed signatures and narrowly scoped trusted patterns, not executable code or unrestricted allow rules. Validate proposals against the existing bounded rule grammar, replay against retained samples, and show expected matches and false-positive evidence. Require review and start in Observe before explicit publication into a versioned policy. Trusted-pattern score reductions must be capped and must not override explicit hard-deny rules. Later automation can use administrator-defined scope, score ceilings, expiry and rollback limits. Provider connectivity alone does not authorize sending logs or enabling automatic enforcement.

This section is a design proposal; the scoring engine and review jobs are not implemented yet.
