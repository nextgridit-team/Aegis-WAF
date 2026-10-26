# Traffic dashboard and application protection

The dashboard is the default signed-in landing page. Select **All applications** or a proxy host, and a 5-, 15-, or 60-minute window. It shows request rates, open connections, in-flight requests, completed requests, unique clients, HTTP response statuses, blocks, bot/flood signals, a traffic chart, country origins and recent requests. Data refreshes every four seconds; access logs normally flush within a second. Statistics use metadata logs independently of opt-in request-content capture.

Request rate (HTTP QPS/RPS) means completed requests over the trailing ten seconds divided by ten. Chart buckets also cover ten seconds. Connections count actual sockets on the public HTTP/HTTPS listeners, including idle keep-alive and upgraded WebSockets. Management traffic is excluded. Each socket is attributed to applications it has served until it closes. An HTTP/2 socket may serve multiple hostnames, so application counts cannot be summed to obtain a global total. In-flight requests are measured separately.

Every replica publishes a small PostgreSQL heartbeat once per second. The dashboard aggregates replicas reporting within ten seconds; a failed replica can remain visible during that interval. Access logs are best effort, so statistics can undercount during queue saturation or database outages. The dashboard warns when reporting replicas have dropped logs since starting. No synthetic traffic is added to product statistics; live-map animations represent recorded requests, and unavailable locations stay explicit.

## Country map

Choose **Enable map locations**, review the DB-IP Lite CC BY 4.0 license, and download the current country database. This is an outbound database download; no visitor IP is sent to a geolocation service. PostgreSQL stores the database, each replica caches it in memory, and configuration version refresh distributes updates. Existing cached data survives database unavailability. A failed download preserves the previous database. Use **Update database** periodically for a new monthly release.

Geolocation is an approximate country estimate, not a precise visitor location. Countries are shaded by request count and have hover tooltips. Private networks and missing records appear under Unknown / private network unless an IP object is explicitly marked Local network and a public location reference is configured in Address objects. Assigned local locations are display metadata; request details retain the actual client IP and observed country. Geo-blocking still uses the actual client IP. See [local network location](address-objects.md#local-network-location). Only new requests gain location metadata after installation; older records remain unknown. DB-IP attribution links remain visible and Natural Earth boundaries are public domain.

## HTTP flood protection

Set **Application protection** while creating/editing a proxy host, or open the dashboard’s **Protection settings**, select the application, and choose Off, Observe or Block. Routing and protection submitted together are validated and saved in one database transaction. Default is Off. Observe flags exceeded limits but allows requests; Block rejects exceeded limits with HTTP 429 and `Retry-After: 1`. Independent token buckets enforce a per-client rate/burst and an aggregate application rate/burst. Local-mode limits are **per replica**: additional replicas increase aggregate capacity. Optional **System → Rate-limit state** Redis/Dragonfly counters share budgets across replicas. No per-request PostgreSQL lookup is required. Bounded in-memory budgets continue during database outages, expire idle client buckets after at least five minutes and their full refill interval, and reset on process restart. At the 100,000-budget capacity, new identities exceed the limiter rather than evict existing budgets. Enforcement uses the same Observe/Block choice.

These controls protect HTTP application throughput; they do not provide network-layer volumetric DDoS protection. Existing server header/read/idle timeouts still apply. ACME challenge requests bypass application protection.

## Bot signals

Bot mode independently offers Off, Observe and Block. Without CAPTCHA enabled, scanner/headless User-Agent signals retain the basic observe/block behavior. Missing User-Agent detection is optional.

Enable **Challenge suspected bots with self-hosted CAPTCHA** in the policy or unassigned application settings for selective verification. Suspicion scores combine declared automation, header/path signals and frequency. Website hosts use the browser challenge; API/SSE hosts instead return JSON denials in Block mode and omit browser-header mismatch scoring. Below-threshold requests receive no challenge. Observe records would-challenge decisions; Block asks suspicious clients to solve a local image/audio challenge. A successful solve grants expiring application/client-bound clearance from repeat challenges, while CIDR/Geo, flood limits and signatures still apply.

Headers can be spoofed and bots can solve CAPTCHA. This does not provide verified-bot identity, behavioral learning or network-layer DDoS protection. Start in Observe and tune for legitimate clients. See [scores, API clients, clearance and database-failure behavior](bot-protection.md).

## Client identity behind proxies

By default the transport peer is the client. List explicit trusted proxy CIDRs per application only for proxies you control that sanitize `X-Forwarded-For`. Aegis walks that header from the transport peer towards the client and stops at the first untrusted hop. Direct untrusted requests cannot spoof their identity using forwarding headers. Choose X-Forwarded-For, X-Real-IP or CF-Connecting-IP as the incoming client-IP source. Single-address headers are accepted only from trusted proxies and must contain one valid address. Missing/malformed/oversized trusted-proxy identities fall back to the transport peer for logging/limits and cannot claim CIDR exemptions. Trust-all CIDRs are rejected. IPv4 and IPv6 are supported.

The resolved IP is used consistently for rate limits, rule `client_ip`, metadata logs, captured client identity and country lookup. Using Cloudflare for DNS certificate verification does not by itself mean application traffic is proxied through Cloudflare. Keep trusted proxies empty for direct connections.

## Component exemptions

The application create/edit form and dashboard protection editor provide separate HTTP flood and Anti-bot exemption IP/CIDR lists. A flood exemption bypasses both client and application budgets and does not consume them; bot detection and declarative rules remain active. Bot exemptions leave flood protection and rules active. Every request remains counted/logged, with explicit exemption metadata and dashboard/Activity labels. Lists start empty and must be configured explicitly. See [header and CIDR controls](headers-and-cidrs.md).

## API

- `GET /api/dashboard?site_id=<optional>&minutes=5|15|60`
- `GET /api/protection-settings`
- `PUT /api/protection-settings/{site_id}`
- `POST /api/geolocation/update` with `{"accept_license":true}`

All require an administrator session; writes also require CSRF protection. Protection changes are stored and audited transactionally and reach replicas through normal version-based refresh. Public traffic continues using the last valid snapshot during database outages; management requests report failures.

## System performance

The dashboard shows CPU percentage and RAM bytes across active gateway replicas, with an expandable per-replica table and configured memory limits. Measurements are global even when traffic is filtered by application. CPU uses changes in consumed CPU time normalized to available cores and the container CPU quota. On Linux cgroup v2, RAM includes memory charged to the container; process resident memory is the fallback. PostgreSQL and other host services are excluded. Sampling runs in the background with existing telemetry and requires no additional containers, host mounts or privileges.

Samples use the one-second telemetry heartbeat; the dashboard refreshes every four seconds. Replica heartbeats expire after ten seconds. Unavailable or initial CPU samples display Unavailable rather than a fabricated zero. This is live telemetry, not a historical resource monitoring service. [Linux cgroup v2 reference](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## Response status and address names

Response status now groups the selected traffic by proxy host, response source and HTTP code. Columns label the request count and percentage of all completed requests in the current application/time range. Up to 100 most frequent groups appear; percentages may therefore sum to less than 100 when more groups exist. Proxy-host names and configured hostnames are current configuration, not reconstructed historical request hosts. Deleted hosts retain their IDs and counts.

New request logs record `response_source`: `upstream`, `waf`, `redirect`, or `gateway_error`. An upstream 403/502 remains an upstream response; gateway-generated errors are identified separately. Older records without provenance show Not recorded unless a recorded block explicitly establishes a WAF response. Sources also appear in individual request details.

Client displays in Dashboard, Activity, regional requests and request details use the most specific currently matching IP object (individual address before a wider CIDR), with up to eight equally specific object names. The original IP remains visible. Names are resolved on management reads, so renames appear without rewriting logs or adding any query to forwarding. A matching object is a display label, not an allowlist or trust decision.

## Live traffic map

Use the **Live traffic map** button beside the Dashboard title (the traffic chart also links to it). It has no separate sidebar entry. The page polls the recorded event tail once per second, animating allowed requests green and recorded WAF blocks red, with an auto-following request log, application filter, pause/resume and request details. The gateway and request animations use approximate regional coordinates from the local City database when available, with a country-area fallback. Configure the Gateway public IP under Address objects to locate Aegis and marked local objects. Unlocated source markers appear only when the feed contains unknown traffic. These are approximate locations, not precise visitor coordinates. Unknown traffic is not assigned a fabricated geographic origin.

The feed shows completed requests after asynchronous logging, usually 1–2 seconds later; active long streams appear upon completion. It reads up to 200 records from the last minute per refresh, deduplicates recent IDs, retains 200 visible log rows and caps simultaneous animations at 30. This is a best-effort visualization, not an exhaustive event-delivery protocol or a TCP connection counter. Activity retains the database records. Pause affects only the view. Reduced-motion preferences disable map animations and initially disable auto-follow; users can control auto-follow explicitly.

### Local traffic flow

Below the live world map, **Local traffic flow** shows Aegis WAF connected directly to each configured proxy host. New observed requests produce green allowed or red blocked pulses along those links. Click a host to filter the world map and request log, or use its application link to open the hostname. **All applications** restores the global view. Collapse the diagram to make room for the log. Disabled routes are labeled explicitly. Per-host allowed/blocked counts describe the bounded live feed sample (up to 200 requests in the last minute); these are not active health checks or complete traffic totals. Upstream endpoints are not shown. Pulses use newly observed events only, are capped at 16 simultaneous effects, respect reduced motion, and stop when the view is removed.

Live coordinates are read from each replica’s cached City database on the management path, matching the event’s recorded country. Local-assigned events use the recorded reference IP; other events use the actual client IP. There are no external lookups per client and no additional forwarding work. Existing log locations are unchanged; coordinates describe the currently installed dataset.

### Hide local traffic

**Hide local traffic** is a browser view preference shared between Dashboard and Live traffic map. On Dashboard it filters the world map, origin list and regional drill-down; overview totals, connection counters and the main recent-requests table still include all traffic. In the live view it filters incoming animations, the displayed log and local-flow sample counts. Aegis and configured routes remain visible. Activity and stored logs retain every recorded request; protections are unchanged.

The filter uses the recorded Local network classification (`local_reference` or `local_unlocated`) from IP objects, not all private addresses. Records made before enabling Local network are not retrospectively reclassified. The default shows all traffic. Filtering happens before the live feed limit so local traffic does not crowd out external events.

See [shared counter configuration and failure handling](shared-rate-state.md) before scaling flood or bot-frequency enforcement.

## System settings and standard monitoring

**System → Rate-limit state** selects local memory or optional shared Redis/Dragonfly counters. The policy still defines rates, bursts and exemptions. The connection test checks draft settings without activating them. **System → Prometheus metrics** links to authenticated management `/metrics`; scrape every replica for cluster totals. See [counter failure behavior](shared-rate-state.md) and [metric meanings](observability.md).

Geo enforcement belongs to **Policies → Edit → CIDR access and Geo blocking**, not the map's display settings. That section is collapsed initially. Set Geo mode, country-list behavior, country codes and unknown-location behavior, then save the policy assigned to the application. [Geo setup](geolocation.md#apply-geo-blocking-to-an-application).
