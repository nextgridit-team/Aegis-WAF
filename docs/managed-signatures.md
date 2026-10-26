# Managed signature sets

Use **View signatures** on an available or loaded set to search and filter its individual IDs, descriptions, categories, severity and paranoia levels. Request rules are shown by default; setup and response entries are separately labeled, and response rules run only when response inspection is enabled in the policy. **Apply to policy** opens a new or existing policy with the set preselected, preserving existing groups and application assignments until an explicit save. In the policy editor, **Browse signatures and exclusions** selects individual rule exclusions; these update the existing excluded-ID field and take effect only when the policy is saved.

New installations and upgrades include the bundled set and an editable **Baseline protection** policy: Block, paranoia 1, anomaly threshold 5 and a 1 MiB request-body limit; bot/flood controls are off. It is not assigned to existing applications automatically. Select it in **Initial protection policy** when adding a proxy host or assign it from Policies. Provisioning happens once under the database initialization lock; restarts and future upgrades preserve administrator edits/deletion.

Use **Rules → Signature sets → Load signature set** to load a new bundled version into PostgreSQL. Then edit a policy in **Policies**, select the loaded version and choose Observe. Assign the policy to applications on the same page. Review matches before choosing Block. The policy editor can also load the bundle inline without discarding entered form values.

Loaded sets are immutable: a policy references a specific identifier, version and checksum. Image updates do not replace those stored bytes. New bundled versions must be explicitly loaded and selected. Custom JSON signatures and URL feeds remain available in rule groups alongside the managed set. No model output or URL feed can supply arbitrary Coraza/SecLang directives through this feature.

The implementation uses Coraza v3.8.1 and bundled CRS v4.30.0 for request headers, URI/query parameters and bounded request bodies. Optional response inspection is off by default. Web profiles check bounded eligible bodies before forwarding; SSE/streaming profiles use overlapping windows after delivery and may terminate the remaining stream. Protocol upgrades, binary gRPC and unsupported types have no body inspection. See [body inspection controls](body-inspection.md). Configuration and compiled WAF instances load with the background snapshot. Routing, certificate selection and signature matching make no per-request database or model calls.

Each policy chooses Off, Observe or Block, paranoia level 1–4, inbound anomaly threshold, request-body inspection limit (default 64 KiB, configurable 4 KiB–1 MiB), and up to 100 targeted known rule-ID exclusions. Global policy Off disables signatures; global Observe caps their mode to Observe. The default oversized-request action rejects in Block with 413. Administrators can instead select bounded prefix inspection and full forwarding; signatures and parser errors can still reject the request. Observe forwards oversized bodies and marks capped inspection; incomplete data is not a clean verdict. At most eight distinct managed configurations can be active, and inspection/buffer reservations are bounded per replica. Observe saturation is recorded and allowed; enforcing saturation fails with 503 rather than skipping inspection.

Logs record policy/version, set/version, effective request/response modes, separate inspection statuses and bounded request/response rule IDs. Matched values, request collections and Coraza audit/debug logs are not persisted by this integration. Optional evidence remains governed by its independent allowlist and redaction settings. Existing fact replay evaluates the custom DSL; it cannot faithfully replay all CRS transformations from incomplete/redacted samples.

The optional sealed recovery cache includes active signature bundles and compiled settings, so an explicitly cached replica can restore protection without PostgreSQL at startup. All serving replicas must run a build supporting managed signatures before policies enable them. Rolling back to an older build without this feature removes its enforcement; use a compatible rollback build or explicitly disable it first.

CRS broadens request and optional response-signature coverage; separate Aegis bot controls provide selective self-hosted CAPTCHA. Neither supplies verified-bot identity, behavioral learning or guaranteed attack/false-positive coverage. Application-specific tuning is still required. Stored corpus versions can be reused by later compatible builds, with replay/testing required when the Coraza implementation itself changes.

Authenticated `GET /api/signature-sets/{id}/rules` returns static corpus metadata for the current available bundle or a stored version. It does not load the bundle, publish a policy or return raw SecLang/matched request values. Inventory metadata is compiled on the management path and cached separately from active enforcement.

## Inventory and policy editor

Actual browser captures from the isolated acceptance fixture, with test-only configuration:

![Searchable CRS inventory with rule metadata and scope filters](screenshots/signature-inventory.png)

![Policy signature browser with an individual CRS exclusion selected before saving](screenshots/signature-exclusions.png)
