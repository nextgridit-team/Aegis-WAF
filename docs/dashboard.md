# Traffic dashboard and application protection

The dashboard is the default signed-in landing page. Select **All applications** or a proxy host, and a 5-, 15-, or 60-minute window. It shows request rates, open connections, in-flight requests, completed requests, unique clients, HTTP response statuses, blocks, bot/flood signals, a traffic chart, country origins and recent requests. Data refreshes every four seconds; access logs normally flush within a second. Statistics use metadata logs independently of opt-in request-content capture.

Request rate (HTTP QPS/RPS) means completed requests over the trailing ten seconds divided by ten. Chart buckets also cover ten seconds. Connections count actual sockets on the public HTTP/HTTPS listeners, including idle keep-alive and upgraded WebSockets. Management traffic is excluded. Each socket is attributed to applications it has served until it closes. An HTTP/2 socket may serve multiple hostnames, so application counts cannot be summed to obtain a global total. In-flight requests are measured separately.

Every replica publishes a small PostgreSQL heartbeat once per second. The dashboard aggregates replicas reporting within ten seconds; a failed replica can remain visible during that interval. Access logs are best effort, so statistics can undercount during queue saturation or database outages. The dashboard warns when reporting replicas have dropped logs since starting. There are no synthetic visitors, connection animations or fabricated locations.

## Country map

Choose **Enable map locations**, review the DB-IP Lite CC BY 4.0 license, and download the current country database. This is an outbound database download; no visitor IP is sent to a geolocation service. PostgreSQL stores the database, each replica caches it in memory, and configuration version refresh distributes updates. Existing cached data survives database unavailability. A failed download preserves the previous database. Use **Update database** periodically for a new monthly release.

Geolocation is an approximate country estimate, not a precise visitor location. Countries are shaded by request count and have hover tooltips. Private networks and missing records appear under Unknown / private network. Only new requests gain location metadata after installation; older records remain unknown. DB-IP attribution links remain visible and Natural Earth boundaries are public domain.

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
