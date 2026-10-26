# Legacy model-provider configuration

The current dashboard uses **Agent access** to connect an external agent through MCP. Configure that agent's model/provider in its own system; Aegis runs no inference or traffic-analysis job. See [current MCP setup, scopes and simulation](agent-access.md). The former **AI backend** provider form is not a current dashboard page.

Compatibility management routes remain implemented: `GET/PUT/DELETE /api/ai/provider` and `POST /api/ai/provider/test`. They can store a revisioned OpenAI-compatible endpoint/model configuration and discover model metadata. They do not enable inference, send traffic for analysis or authorize automatic policy changes. Normal session/CSRF or permitted MCP Configuration scope applies.

Discovery calls the endpoint's `/models` route with optional Bearer authentication, bounded size/time/model counts and verified TLS. It does not follow redirects or use environment proxies. Public endpoints require HTTPS; private/loopback providers can use HTTP. Link-local/metadata endpoints are rejected. Saved API keys are encrypted by the application before PostgreSQL storage, using the external encryption key; normal read APIs return no key. Endpoint changes require replacement or explicitly cleared credentials rather than forwarding a saved secret to another destination.

## Historical proposal: built-in review jobs

The notes below predate the external-agent/MCP direction. They remain design history, not a shipped workflow or commitment to run an LLM inside Aegis. The operator's agent owns its model, sharing policy and playbook; live protection changes follow the enforced simulation gate.

### Scoring and background review

Keep deterministic rules and rate limits on the synchronous request path. Assign bounded weights to explainable signals and deny at a policy-defined threshold. High-confidence signatures may directly deny; weaker independent signals can accumulate. Avoid counting correlated rules repeatedly. If sender/endpoint risk persists between requests, use a bounded expiring cache and document replica-local behavior. A reputation store must never introduce a database or model dependency for each request.

Run periodic, PostgreSQL-coordinated review jobs per application and a configurable lookback window. Begin with aggregates by endpoint and resolved sender, status mix, rates and existing rule matches; use opt-in redacted samples only when needed. Limit rows, tokens, cost, concurrency and execution time. Treat all traffic fields as untrusted input, including text that attempts to instruct the model.

The model should propose typed signatures and narrowly scoped trusted patterns, not executable code or unrestricted allow rules. Validate proposals against the existing bounded rule grammar, replay against retained samples, and show expected matches and false-positive evidence. Require review and start in Observe before explicit publication into a versioned policy. Trusted-pattern score reductions must be capped and must not override explicit hard-deny rules. Later automation can use administrator-defined scope, score ceilings, expiry and rollback limits. Provider connectivity alone does not authorize sending logs or enabling automatic enforcement.

This section is a design proposal; the scoring engine and review jobs are not implemented yet.
