# Protection policies

Use **Policies** to create reusable protection and assign it to one or more applications. Each policy has Off, Observe or Block mode, independent bot/flood switches, configurable per-client and per-application flood budgets, and up to ten named rule groups. A group's optional path prefix and method list narrow all its signatures. The signature's own conditions and path prefix also apply.

**Rules** is one workspace with Signatures and Rule feeds tabs. Create or import signature drafts there, then select them in policy groups. A published policy stores frozen copies: editing a signature or syncing a feed never silently changes live policy enforcement. Check **Refresh selected rule snapshots from the library** and save to publish changes. Policy History restores protection and signature snapshots for current application assignments; it does not restore historical assignments. Revisions reject stale saves. Policies have explicit administrator-controlled lifetimes; standalone rule activation keeps its existing TTL behavior.

## External and internal traffic

Assign an External policy with **All other clients · default** first. Then assign an Internal or office policy to specific IPs/CIDRs with a priority of 0–9999. Smaller priorities match first. Every application using scoped policies must retain one default; choosing a new default replaces its old assignment atomically. Overlapping CIDRs use priority rather than longest-prefix matching. At most ten policies can be assigned to an application.

Client identity is resolved using the application's trusted proxy settings. A direct visitor cannot select an internal policy by forging forwarding headers. Missing or invalid identity from a trusted proxy is eligible only for the default policy. Selecting a trusted policy does not automatically allow traffic: its configured groups, mode and bot/flood protection determine the action.

Assigned policies replace local bot/flood and standalone rule activation for that application. Applications without assignments keep existing local behavior. Headers, trusted proxies and component CIDR exemptions remain application settings. Flood budgets are per application, selected policy and replica; trusted-policy traffic does not consume an external policy's budget. Limits are not globally coordinated rate counters.

Configuration and frozen signatures live in PostgreSQL and propagate through the normal two-second snapshot refresh. Requests select cached policies without database or model calls. Metadata logs identify the selected policy and version. Policy saves, default reassignment, deletion and rollback produce administrative audit events.

The current engine uses deterministic matching and blocking. Weighted scoring, endpoint-specific rate policies, coverage recommendations and AI-generated policy changes are future work.
