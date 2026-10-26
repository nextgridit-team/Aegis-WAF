# Local Geo data, regions and policy controls

Use **Dashboard → Database sync & regions** to download DB-IP Lite Country or optional City data after accepting its CC BY 4.0 license/attribution. Country downloads support policy decisions; City data adds first-level subdivisions (states/regions) to newly logged requests. No per-visitor network queries are made. [DB-IP Lite](https://db-ip.com/db/lite.php), [City format](https://db-ip.com/db/format/ip-to-city-lite/mmdb.html).

The download is a PostgreSQL-coordinated background job, visible as queued/running/ready/retry. Optional automatic sync checks the next monthly release; manual queuing is also available. Replicas share one job lease per data kind. Downloads, decompression and MMDB parsing are bounded; failures retain the prior data and retry with backoff. Country data is limited to 32 MiB; City archives to 192 MiB and decompressed City data to 512 MiB. These are safety caps, not memory usage estimates: downloads, database transfers and readers can require additional transient copies. City datasets require substantially more RAM/database storage per replica than Country alone.

Country enforcement uses the normal cached snapshot (two-second version polling by default). Regional enrichment has a separate five-second cache refresh so large City blobs are excluded from route/certificate snapshots and optional sealed recovery files. Logs are enriched off the forwarding path. An offline cold start from a sealed snapshot can enforce its cached country policy but region enrichment remains unavailable until database connectivity returns. Selecting Country only disables future City enrichment after refresh, retaining stored data and existing logs.

Click a country on the world map to see region counts; the US additionally displays a clickable state map with Alaska, Hawaii and DC. Click a state/region to see its recent requests, then **View details** to investigate an individual request. Filters retain the selected application and time window. Unknown locations remain explicit: old records are not backfilled. Non-US countries show regional tables rather than fabricated subdivision maps. State boundaries are Census-derived US Atlas data, with [notices](../third_party_licenses/maps/us-atlas/LICENSE).

In a policy, evaluation order is verified client identity → policy selection → CIDR block → CIDR allow → Geo → remaining WAF protections. Blocks win CIDR overlaps. Allow behavior is a per-policy choice: **Geo only** or **all WAF protections**. Unreliable forwarded identities cannot use allow entries. Unknown-country behavior is explicit Allow/Block. Policy Off disables these controls; Observe records would-block decisions without rejecting. Geo requires a downloaded Country database before enabling. CIDR hits skip Geo enforcement lookups; optional regional log enrichment still occurs asynchronously.

## Apply Geo blocking to an application

1. Download the Country database under **Dashboard → Database sync & regions** if it is not already available. Review and accept the dataset license.
2. Open **Policies**, choose **Edit** on the policy, and expand **CIDR access and Geo blocking**. This section is collapsed initially.
3. Set **Geo mode** to **Block**. Choose **Country list behavior**: block the selected countries, or allow selected countries and block other known locations.
4. Enter two-letter **Country codes**, choose **Unknown location behavior**, and save the policy. The policy itself must be in Block to enforce; Observe records decisions without blocking.
5. Confirm the intended application appears under **Application assignments**. Editing a shared policy changes every application assigned to it. Use a separate policy when applications need different country rules.

CIDR block/allow decisions run first. A Geo-only allow entry skips Geo while retaining other protections; an all-WAF allow entry bypasses the rest of the WAF. A local-map location reference changes display metadata, not the real client IP used for enforcement. Inspect the recorded network decision in request details after the normal refresh interval. See [policy selection](policies.md).

IP geolocation is approximate; VPNs/proxies can relocate apparent visitors. Private/non-global addresses and missing records are unknown. Logs store country and first-level region codes/names, not city coordinates or street addresses. These fields remain potentially personal data with existing client IPs; apply your deployment's retention/access/data-residency rules. Free datasets have reduced accuracy and coverage.
