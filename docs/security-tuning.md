# Inspection bounds, exclusions and security telemetry

## Request-body inspection

Body inspection uses bounded prefixes, not an unbounded `io.ReadAll` of visitor data. Custom JSON fact extraction reads at most 64 KiB + one sentinel byte, bounds nesting and token counts, and replays consumed bytes upstream. Managed signatures inspect 4 KiB–1 MiB per policy with 64 concurrent inspection reservations per replica. Block mode rejects oversized bodies (413) or unavailable inspection capacity (503). Observe mode forwards the full original body and marks capped/busy inspection. Reservations are released when the buffered prefix is forwarded or the body is closed, without waiting for response streaming or WebSocket lifetime.

A bounded prefix is buffered before forwarding so Block can decide before sending attack bytes upstream. Streaming data upstream while deciding whether to block would already expose the upstream. Uninspected data is never described as fully inspected. Evidence uses a bounded tap while the upstream reads, not a separate read-ahead operation. Configuring a larger body limit increases concurrent memory requirements; these bounds do not cap all HTTP/TLS/Coraza/process memory.

## False-positive tuning

Policy Signature tuning supports global rule-ID exclusions and **Scoped signature exclusions (JSON)**. Settings persist through the dashboard/API in PostgreSQL; no configuration files need editing. For example:

```json
[
  {
    "rule_ids": [942100],
    "path_prefix": "/search",
    "parameters": ["q"],
    "client_cidrs": ["192.168.10.0/24"]
  }
]
```

This exempts argument `q` from rule 942100 only when both the path prefix and verified source range match. Other arguments, rules and paths still apply. Omitting parameters exempts those entire rules within the selected path/client scope. Parameter-only exceptions apply across paths. Client predicates cannot use an unreliable forwarded identity. Scopes are literal prefixes/CIDRs/argument names, not administrator-provided SecLang. Up to 32 entries, 20 IDs and 16 parameters/client CIDRs each; rule IDs must exist in the selected set and be detection IDs 910000–948999. Scoring/control IDs cannot be conditionally excluded. Parameter names refer to Coraza ARGS (query/form and the corresponding parsed JSON argument names), not arbitrary HTTP headers or raw-body byte offsets.

Exceptions do not prove that a request is safe. Investigate allowed and blocked traffic, replay both attack and benign retained facts for custom rules, and use Observe before broadening exclusions.

## Structured events and privacy

Application diagnostics and security events use JSON on stdout. The bounded background access-log worker emits security metadata after the traffic decision, before attempting the PostgreSQL batch write. A failed database write therefore does not suppress an otherwise queued stdout event. Slow logging can fill/drop the bounded queue; it does not wait in forwarding. Events are best-effort, not a guaranteed SIEM delivery stream.

Security events use `event` values `waf_block`, `waf_observe`, or `waf_allow` (explicit full WAF bypass). Fields include request timestamp, source IP, site/policy/revision, status, custom `rule_ids`, CRS `signature_ids`, signals, and network decision. No raw matched payload, authorization/cookie headers, key or body is included by default. An unmatched allowed request remains in PostgreSQL access logs without producing a security stdout event.

In **Traffic → Capture settings**, administrators can disable security stdout events per application or explicitly include retained redacted request samples. `security_events_disabled` and `security_samples` are also TrafficSettings API fields. Samples require the existing opt-in sampling policy and field allowlists; only sampled retained facts are emitted, capped at 2 KiB. `request_sample` is context, not a guaranteed exact matched string. Truncation can leave a JSON-looking string incomplete. Redaction is best-effort; stdout collectors and agents may export personal data outside PostgreSQL retention controls. Audit events contain operation metadata, never sample values or credentials.

## Regression checks

The attack matrix includes SQL injection, XSS, traversal, encoding variants and benign controls through Coraza/CRS. Separate tests verify scoped exclusions, tiny transport chunk boundaries, bounded read-ahead, exact body replay, reservation release and telemetry privacy. A prompt-injection case exercises an explicitly configured native literal rule only: CRS is not a general semantic prompt-injection detector.

Go fuzzing checks JSON fact extraction, read bounds, malformed input and exact body preservation. Seed cases run with ordinary `go test`; CI additionally runs 20 seconds with two fuzz workers. Pull requests and branch pushes run the security workflow. Main pushes, nightly builds and manual image builds must pass this reusable workflow before the image publication job starts. Detection tests and fuzzing reduce regressions; they do not establish complete attack coverage or absence of bypasses.
