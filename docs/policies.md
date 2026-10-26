# Protection policies

Use **Policies** to create reusable protection and assign it to one or more applications. Each policy has Off, Observe or Block mode, independent bot/flood switches, configurable per-client and per-application flood budgets, and up to ten named rule groups. A group's optional path prefix and method list narrow all its signatures. The signature's own conditions and path prefix also apply.

**Rules** is one workspace with Signatures, Rule feeds and Signature sets tabs. [Managed signature sets](managed-signatures.md) can be selected directly in a policy. Create or import signature drafts there, then select them in policy groups. A published policy stores frozen copies: editing a signature or syncing a feed never silently changes live policy enforcement. Check **Refresh selected rule snapshots from the library** and save to publish changes. Policy History restores protection and signature snapshots for current application assignments; it does not restore historical assignments. Revisions reject stale saves. Policies remain configured until explicitly changed or removed; standalone rule activation keeps its existing TTL behavior.

## Included baseline

**Baseline protection** ships with request-side CRS enabled in Block mode, paranoia level 1, anomaly threshold 5 and a 1 MiB body limit. Bot and flood controls are off because their appropriate budgets vary by application. Requests above the body limit receive 413 when this policy enforces; tune upload-heavy applications before assignment.

Choose this policy under **Initial protection policy** when creating a proxy host, or assign it from this page. Site creation and initial policy assignment commit atomically; a failed assignment creates neither. Omitting that choice preserves local application settings. Existing applications are never reassigned automatically. The baseline can be edited, renamed or deleted, and provisioning will not recreate or overwrite it on restart. Up to 50 custom policies are supported in addition to the included baseline.

## External and internal traffic

Assign an External policy with **All other clients · default** first. Then assign an Internal or office policy to specific IPs/CIDRs with a priority of 0–9999. Smaller priorities match first. Every application using scoped policies must retain one default; choosing a new default replaces its old assignment atomically. Overlapping CIDRs use priority rather than longest-prefix matching. At most ten policies can be assigned to an application.

Client identity is resolved using the application's trusted proxy settings. A direct visitor cannot select an internal policy by forging forwarding headers. Missing or invalid identity from a trusted proxy is eligible only for the default policy. Selecting a trusted policy does not automatically allow traffic: its configured groups, mode and bot/flood protection determine the action.

Assigned policies replace local bot/flood and standalone rule activation for that application. Applications without assignments keep existing local behavior. Headers, trusted proxies and component CIDR exemptions remain application settings. Flood budgets are per application and selected policy; trusted-policy traffic does not consume an external policy's budget. Local mode is per replica; optional Redis/Dragonfly mode coordinates counters across replicas. See [shared rate state](shared-rate-state.md).

Configuration and frozen signatures live in PostgreSQL and propagate through the normal two-second snapshot refresh. Requests select cached policies without database or model calls. Metadata logs identify the selected policy and version. Policy saves, default reassignment, deletion and rollback produce administrative audit events.

Native rules use deterministic matching and blocking; managed CRS uses its own anomaly scoring. Native weighted scoring, endpoint-specific rate budgets and built-in AI policy generation are not implemented. External agents can propose and apply scoped, simulated changes through MCP.

## Configure the recent controls

- **Geo:** Edit the policy and expand **CIDR access and Geo blocking**. Set Geo mode, country-list behavior, country codes and unknown-location behavior. The Country database must be downloaded first. [Step-by-step Geo setup](geolocation.md#apply-geo-blocking-to-an-application).
- **Selective CAPTCHA:** enable anti-bot signals and **Challenge suspected bots with self-hosted CAPTCHA**. Tune the threshold, frequency and clearance window; Observe never challenges. Clearance does not bypass other protections. [Bot verification](bot-protection.md).
- **Response inspection:** use **Managed signatures → Signature tuning**. Response mode defaults Off. Web profiles buffer eligible bodies; SSE/streaming profiles inspect after delivery. Endpoint type/window belong to the proxy host. [Inspection controls](body-inspection.md).
- **Shared budgets:** select the deployment-wide backend under **System → Rate-limit state**; policy rates still set the budgets. Local is per replica; optional Redis/Dragonfly is shared. [Backend setup](shared-rate-state.md).

MCP agents must simulate the exact protection mutation and provide a fresh `simulation_id`; dashboard administrators continue using session/CSRF authorization. Rules, CIDR lists and TLS configuration compile into a new snapshot before an atomic swap. Open requests keep their admitted configuration; new requests use the refreshed one. [Agent safety gate](agent-access.md#required-simulation-before-live-protection-changes) · [Reload behavior](architecture.md#atomic-reload-and-active-connections).
