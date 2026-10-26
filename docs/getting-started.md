# Get your first application protected

## Start Aegis and create an administrator

Use the [four-command quickstart](../README.md#quickstart) or the [deployment guide](deployment.md). The default management address is `http://localhost:9090` on the Docker host. Read `secrets/bootstrap_secret` locally, then create your administrator in the browser using a unique 14–72-byte password. There are no default credentials; the setup code does not reset an existing account.

For a server or Dockge deployment, use the [HTTPS management instructions](deployment.md#remote-https-management). A browser on your laptop cannot reach the server through the laptop's localhost address.

## Add certificates, routing and protection

1. **Get a certificate.** Open **Certificates → Request certificate**. For Cloudflare DNS-01, enter domains, email and an API token scoped to the zone with **Zone Read** and **DNS Edit**, then explicitly accept the CA terms. Aegis handles account registration, validation, issuance and renewal. DNS-01 needs no inbound port 80. [Cloudflare setup](cloudflare.md) covers permissions and prerequisites. Use **Advanced options** for staging/custom CAs or HTTP-01, or **Upload PEM** for an existing certificate and key.
2. **Connect the upstream.** When issuance succeeds, choose **Connect site**, enter the application's reachable HTTP(S) upstream URL and save. Choose **Endpoint type → API** for machine clients, **SSE / streaming API** for streaming services, or **Website** for browser applications. API/SSE use JSON denials and no browser CAPTCHA; policies still control body checks and signatures. In **Proxy hosts**, set its exact hostnames, certificate, redirect and header options. Point client DNS and your port mappings/load balancer at Aegis. The upstream's `localhost` would mean the Aegis container itself.
3. **Choose baseline protection.** New installations and upgrades include an editable **Baseline protection** policy with CRS already loaded: Block mode, paranoia level 1, anomaly threshold 5 and a 1 MiB request-body limit. Select it under **Initial protection policy** while adding a proxy host, or assign it from Policies. Bot/flood controls remain off until tuned. Existing applications are not assigned automatically.
4. **Inspect or customize signatures.** In **Rules → Signature sets**, choose **View signatures** for searchable rule IDs, descriptions and metadata. **Apply to policy** configures a new or existing policy with the set selected. In **Policies**, use **Browse signatures and exclusions** for targeted exceptions. Start custom policies in **Observe**, then assign applications. Add custom rule groups and bot/flood settings as needed. Assign a default policy before adding higher-priority CIDR policies. If Aegis is behind a proxy, configure its trusted addresses and client-IP header first.
5. **Review, then enforce.** Check the Dashboard and Activity for matches. Tune exclusions, body limits and rates, then explicitly choose **Block**. Policy Observe caps managed signatures at Observe; Off disables them. Policy assignments replace that application's standalone rule activation and local bot/flood settings.

Replicas check configuration versions every **2 seconds**; compilation/loading can add time for new managed signature configurations. Local bot/flood controls are Off and evidence capture is disabled. The included baseline enforces CRS only after you explicitly assign it. Deleting or editing that baseline is preserved across restarts; upgrades do not overwrite it. A wildcard certificate covers TLS names; proxy routes still require exact configured hostnames.

## Investigate and tune

Open **Dashboard → Live traffic map** for incoming traffic and the Aegis-to-proxy-host flow. Use **Hide local traffic** to focus the map views on external traffic after marking your [local address objects](address-objects.md#local-network-location). Geo data is downloaded only when enabled; coordinates are approximate.

In Dashboard or Activity, choose **View details** on any listed request to inspect its recorded outcome, policy and signature matches. Request-content evidence is opt-in and cannot reconstruct traffic that was not captured. See [request investigation](request-investigation.md), [policy tuning](policies.md) and [evidence privacy](evidence-privacy.md).

## Enable additional protection and monitoring

Geo controls are under **Policies → Edit → CIDR access and Geo blocking**: download the Country database, choose Geo mode/country behavior and save the policy assigned to the application. [Geo walkthrough](geolocation.md#apply-geo-blocking-to-an-application).

For suspected bots, enable selective self-hosted CAPTCHA in the policy; ordinary below-threshold traffic is not challenged. For replicated flood enforcement, configure **System → Rate-limit state** with an optional shared Redis/Dragonfly endpoint. Local memory remains the default. [Bot verification](bot-protection.md) · [Shared budgets](shared-rate-state.md).

**System → Prometheus metrics** links to the management-only `/metrics` endpoint. A source-restricted Read key can authenticate an HTTPS scraper even with MCP disabled. Scrape every replica. Agents performing live protection changes must first use the [offline impact simulation](agent-access.md#required-simulation-before-live-protection-changes).

## Add targeted community rules

Open **Rules → Rule feeds → Aegis community mitigations → Review** (use **Sync now** first if queued). Search by CVE or technology, review coverage and compatibility, select individual rules or a pack, and **Apply selected to policy**. Save an existing policy or create and assign a new Observe policy before enforcing. Downloads run every 12 hours; published rule copies stay pinned until explicitly refreshed. [Full guide](rule-feeds.md).
