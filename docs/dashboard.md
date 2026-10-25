# Traffic dashboard and application protection

The dashboard is the default signed-in landing page. Select **All applications** or a proxy host, and a 5-, 15-, or 60-minute window. It shows request rates, open connections, in-flight requests, completed requests, unique clients, HTTP response statuses, blocks, bot/flood signals, a traffic chart, country origins and recent requests. Data refreshes every four seconds; access logs normally flush within a second. Statistics use metadata logs independently of opt-in request-content capture.

Request rate (HTTP QPS/RPS) means completed requests over the trailing ten seconds divided by ten. Chart buckets also cover ten seconds. Connections count actual sockets on the public HTTP/HTTPS listeners, including idle keep-alive and upgraded WebSockets. Management traffic is excluded. Each socket is attributed to applications it has served until it closes. An HTTP/2 socket may serve multiple hostnames, so application counts cannot be summed to obtain a global total. In-flight requests are measured separately.

Every replica publishes a small PostgreSQL heartbeat once per second. The dashboard aggregates replicas reporting within ten seconds; a failed replica can remain visible during that interval. Access logs are best effort, so statistics can undercount during queue saturation or database outages. The dashboard warns when reporting replicas have dropped logs since starting. There are no synthetic visitors, connection animations or fabricated locations.

## Country map

Choose **Enable map locations**, review the DB-IP Lite CC BY 4.0 license, and download the current country database. This is an outbound database download; no visitor IP is sent to a geolocation service. PostgreSQL stores the database, each replica caches it in memory, and configuration version refresh distributes updates. Existing cached data survives database unavailability. A failed download preserves the previous database. Use **Update database** periodically for a new monthly release.

Geolocation is an approximate country estimate, not a precise visitor location. Countries are shaded by request count and have hover tooltips. Private networks and missing records appear under Unknown / private network unless an IP object is explicitly marked Local network and a public location reference is configured in Address objects. Assigned local locations are display metadata; request details retain the actual client IP and observed country. Geo-blocking still uses the actual client IP. See [local network location](address-objects.md#local-network-location). Only new requests gain location metadata after installation; older records remain unknown. DB-IP attribution links remain visible and Natural Earth boundaries are public domain.

## HTTP flood protection

Set **Application protection** while creating/editing a proxy host, or open the dashboard’s **Protection settings**, select the application, and choose Off, Observe or Block. Routing and protection submitted together are validated and saved in one database transaction. Default is Off. Observe flags exceeded limits but allows requests; Block rejects exceeded limits with HTTP 429 and `Retry-After: 1`. Independent token buckets enforce a per-client rate/burst and an aggregate application rate/burst. Limits are **per replica**, not a cluster-wide quota: additional replicas increase aggregate capacity. No per-request PostgreSQL lookup is required. Bounded in-memory budgets continue operating during database outages, expire idle client buckets after five minutes, and reset on process restart. At the 100,000-budget capacity, new identities exceed the limiter rather than evict existing budgets. Enforcement uses the same Observe/Block choice.

These controls protect HTTP application throughput; they do not provide network-layer volumetric DDoS protection. Existing server header/read/idle timeouts still apply. ACME challenge requests bypass application protection.

## Bot signals

Bot mode independently offers Off, Observe and Block. The initial detector identifies declared scanner and headless-browser user agents (`sqlmap`, `nikto`, `nuclei`, `masscan`, `zgrab`, `HeadlessChrome`, `PhantomJS`). Missing user agents are optional. Signals are explainable and appear in dashboard totals and access logs. Block returns HTTP 403 unless an exceeded flood limit already requires 429.

User agents are spoofable and legitimate tests/monitoring can match. This is basic signature-based bot detection, with no claim of verified bot identity, browser challenges, fingerprinting, CAPTCHA, behavioral learning or AI. Start in Observe and assess your application's traffic before blocking.

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

Use the **Live traffic map** button beside the Dashboard title (the traffic chart also links to it).  It has no separate sidebar entry. The page polls the recorded event tail once per second, animating allowed requests green and recorded WAF blocks red, with an auto-following request log, application filter, pause/resume and request details. The gateway and request animations use approximate regional coordinates from the local City database when available, with a country-area fallback. Configure the Gateway public IP under Address objects to locate Aegis and marked local objects. Unlocated source markers appear only when the feed contains unknown traffic. These are approximate locations, not precise visitor coordinates. Unknown traffic is not assigned a fabricated geographic origin.

The feed shows completed requests after asynchronous logging, usually 1–2 seconds later; active long streams appear upon completion. It reads up to 200 records from the last minute per refresh, deduplicates recent IDs, retains 200 visible log rows and caps simultaneous animations at 30. This is a best-effort visualization, not an exhaustive event-delivery protocol or a TCP connection counter. Activity retains the database records. Pause affects only the view. Reduced-motion preferences disable map animations and initially disable auto-follow; users can control auto-follow explicitly.

### Local traffic flow

Below the live world map, **Local traffic flow** shows Aegis WAF connected to each configured proxy host and its upstream. Click a host to filter the world map and request log, or use its application link to open the hostname. **All applications** restores the global view. Collapse the diagram to make room for the log. Disabled routes are labeled explicitly. Per-host allowed/blocked counts and recorded upstream responses describe the bounded live feed sample (up to 200 requests in the last minute); these are not active health checks or complete traffic totals. Upstream credentials and query strings are omitted from the diagram.

Live coordinates are read from each replica’s cached City database on the management path, matching the event’s recorded country. Local-assigned events use the recorded reference IP; other events use the actual client IP. There are no external lookups per client and no additional forwarding work. Existing log locations are unchanged; coordinates describe the currently installed dataset.
