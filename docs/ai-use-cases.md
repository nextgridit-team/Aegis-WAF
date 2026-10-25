# Aegis AI Use Cases — Build Sheet

Ground rules that apply to every use case here:

1. No model on the request path. The data plane stays deterministic (208ns). AI runs on the
   evidence plane (batch, over stored data) and the management plane (operator copilot) only.
2. The AI judges, the policy engine acts. Model output is always a *draft* — structured JSON,
   schema-validated, then either replay-validated or human-approved before it affects anything.
   A model never emits enforcement directly.
3. Everything the model reads is attacker-controlled. Evidence values are untrusted data in
   prompts: delimited, marked as data-not-instructions, never interpolated as instructions.
4. Reuse the rails that exist: OpenAI-compatible provider config + model discovery + connection
   test (ai_provider.go) — point it at Ollama/vLLM/llama.cpp in-cluster; RunWorker for the batch
   jobs (panic containment for free); the Postgres evidence/access-event store as input; the
   snapshot refresh as the distribution mechanism for anything replicas must agree on.

---

## Tier 1 — build first

### 1. AI rule drafting with replay validation (flagship)
What the operator sees: pick a site, click "draft rules from evidence". The system analyzes
captured traffic samples and blocked-request evidence for that site, proposes rules in the
existing rule schema, replays each candidate against captured evidence, and shows pass/fail
per rule with the model's rationale. Human approves; rule goes live through the normal path.

Why it's the flagship: the replay-before-enable engine de-risks the LLM completely. A
hallucinated rule is just a rule that fails replay against real traffic. No commercial WAF
offers "generator + deterministic evaluator + human gate" as one loop.

Build:
- New table `ai_proposals` (kind, site, payload JSON, rationale, status: draft/rejected/approved,
  replay_results, created_by, created_at).
- New RunWorker job: query evidence for the site, summarize to a compact context (sampled,
  redacted, size-capped), call the model with a JSON-schema-constrained prompt, validate output
  against the rule schema, feed candidates into the existing replay-before-enable flow, store
  results.
- API: POST /api/ai/rules/draft (kicks off job), GET list, POST approve/reject.
- UI: button + results panel in the rules page.

Effort: M. New surface: inference client + proposal table + one worker + endpoints.

### 2. Block triage and graduated auto-response
What the operator sees: a "Responses" page. Each entry: client IP, what happened (block rate,
rules hit, time window), the AI classification (targeted attack / scanner / monitoring tool /
pentest / unclear), the recommended response tier, and a plain-language explanation. In observe
mode nothing is enforced — entries are drafts. When enabled, tiered responses fire: flag →
per-IP tightened rate limit (429 + Retry-After) → temporary block with TTL.

Deterministic trigger first, AI second:
- The math runs in the worker from access events: blocks per client_ip per window, distinct
  rules/endpoints hit (1 IP → many = scanner; many IPs → 1 endpoint = campaign; 1 IP → 1
  endpoint at high rate = targeted), persistence across windows, ramp shape.
- Only IPs that trip the math get an AI verdict on the gray zone (scanner vs monitoring tool vs
  attack), reading a few redacted evidence samples.
- The thresholds are config, testable, and immune to prompt injection. The AI cannot lower a
  deterministic trigger.

Build:
- New table `ip_responses` (client_ip, action, tier, reason, trigger_stats JSON,
  ai_classification, explanation, created_by 'ai'/'human', expires_at TTL, revoked_at).
- Load active entries in loadSnapshot; enforce in protectResolved (or just before it) keyed on
  the resolved client IP. Distribution to all replicas comes free via snapshot refresh —
  inherently multi-replica/F5-safe.
- Safety rails, non-negotiable: mandatory short TTLs (15m, doubling on repeat, hard cap a few
  hours without human sign-off), cap on total active entries (a few thousand) so junk can't
  bloat the snapshot, allowlists/exemptions always outrank auto-responses, one-click revoke,
  every action logged as evidence.
- Ship observe-only first; tier-1 auto-apply only after a couple of weeks of watching.

Effort: L (new enforcement surface + worker + classification + UI). Highest operational value.

---

## Tier 2 — daily operational value

### 3. False-positive triage in observe mode
Summarize what a rule *would have blocked*: cluster flagged requests, identify the 3-4 sources
composing the volume (e.g. one monitoring scanner = 312 of 340), propose allowlist refinements
or rule tweaks as drafts. Turns the observe-mode wall of rows into a paragraph plus a decision.
Read-only over existing evidence + drafts table from #1. Effort: S-M.

### 4. Attack narrative / incident summarization
Same evidence store, different prompt: week of blocked traffic for a site → campaign summary
(actors, ASNs/geos from the geo field, timeline, escalation, what mitigated it). For audits,
incident reports, and the "why" attached to every auto-response in #2. Falls out almost free
once #3 exists. Effort: S.

### 5. Redaction pattern discovery
Feed already-captured, already-redacted sample values to the model; it proposes additional
`redact_patterns` (field names / value shapes that look like tokens, account numbers, emails).
Human approves; applies to new samples only. Model only ever sees stored untrusted-flagged
evidence; output is a suggestion list. Extends the redaction feature shipped 2026-10-25.
Effort: S.

---

## Tier 3 — later

### 6. Baseline policy learning (positive security model)
Derive the app's real shape from evidence — routes, methods, content types, parameter counts
actually observed over N days — and propose tightening: "this app has never received a PUT in
30 days; consider a method allowlist." This is the thing signature-based WAFs are structurally
bad at. Effort: M.

### 7. Ops copilot over the management API
"Why is site X's cert renewing late?" answered by a model querying existing status endpoints.
Convenience, not security value. Effort: M.

---

## Explicitly out of scope
- LLM calls on the request path: latency is 5-9 orders of magnitude off, output is
  nondeterministic, and request bodies are prompt-injection surface. Not negotiable.
- AI output becoming enforcement without replay or human approval: same rule.

## Shared platform work (build once, serves all cases)
- Inference client in Go (OpenAI-compatible chat endpoint; provider row already stored, sealed).
  All use cases call this.
- `ai_proposals` drafts table + approve/reject endpoints (serves #1, #3, #5, #6).
- Prompt scaffolding: untrusted-data delimiters, JSON schema validation, size caps on context.
- RunWorker job runner pattern per use case; status surfaced like background_worker_panics.

## Sequencing recommendation
#3 first (S-M, pure read + drafts, zero risk, immediate daily value, exercises the whole rail),
then #1 (flagship), then #4 (nearly free), then #2 in observe-only mode, enable tier-1 responses
after a tuning window. #5-#7 as time allows.
