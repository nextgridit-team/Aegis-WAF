# Aegis glossary

Plain-language explanations for settings shown in the dashboard. Click the **?** beside a setting for a short explanation, then **Read detailed explanation** for the built-in glossary. The same glossary is available at the management listener’s **/help.html** and works without Internet access. Full configuration-guide links open GitHub and require Internet access.

This file and the embedded glossary are generated from [the help catalogue](../web/src/help-topics.json). Update that source and run **node web/scripts/build-help.mjs --docs**; check consistency with **node web/scripts/build-help.mjs --check**.

- [Protection policy](#policy)
- [Off, Observe and Block](#observe-block)
- [Managed signatures and OWASP CRS](#signatures)
- [Signature sensitivity](#sensitivity)
- [CRS paranoia level](#paranoia)
- [Anomaly score threshold](#anomaly-score)
- [Curated signature set](#curated-set)
- [Signature exceptions](#exceptions)
- [Body inspection limits](#body-inspection)
- [Response inspection](#response-inspection)
- [HTTP flood protection](#flood)
- [Requests per second](#request-rate)
- [Burst allowance](#burst)
- [Bot detection and CAPTCHA](#bot)
- [Bot suspicion threshold](#bot-score)
- [Bot clearance duration](#clearance)
- [IP addresses, CIDRs and subnets](#cidr)
- [IP address objects and groups](#address-object)
- [Allow-list bypass](#allow-bypass)
- [Component protection exemptions](#component-exemptions)
- [Geo blocking](#geo)
- [Trusted proxies and client identity](#trusted-proxy)
- [Forwarded headers](#forwarded-headers)
- [Policy assignment priority](#priority)
- [Community mitigations](#community)
- [Rule groups](#rule-groups)
- [Rule feeds and pinned snapshots](#feed)
- [Proxy host and upstream](#proxy-host)
- [Website, API and streaming endpoints](#endpoint-type)
- [TLS and HTTPS certificates](#tls)
- [ACME certificate automation](#acme)
- [DNS verification (DNS-01)](#dns-challenge)
- [HTTP verification (HTTP-01)](#http-challenge)
- [Certificate staging and production](#staging)
- [PEM chains and private keys](#pem)
- [HSTS browser protection](#hsts)
- [MCP agent access](#mcp)
- [API key scopes and allowed sources](#api-scope)
- [Rule simulation and replay](#simulation)
- [Request evidence and redaction](#evidence)
- [Webhooks and alert destinations](#webhook)
- [Prometheus metrics](#metrics)
- [Replicas and shared rate state](#replicas)
- [Audit events and access logs](#audit)
- [Local traffic map location](#local-location)
- [Bootstrap secret](#bootstrap)
- [Upstream TLS trust](#upstream-tls)
- [Allowed HTTP methods](#http-methods)
- [API starting settings](#api-start)
- [Connection and stream limits](#connection-limits)
- [Streaming inspection window](#stream-window)

<a id="policy"></a>

## Protection policy

A policy is a saved collection of protection settings that you can reuse across applications. Assign it to a proxy host to choose how that application handles traffic.

An assigned policy controls bot/flood settings and its selected rules. Applications can have a default policy and additional policies for specific client networks; the application still controls routing, headers and trusted proxies.

[Configuration guide](policies.md)

<a id="observe-block"></a>

## Off, Observe and Block

Off pauses that protection; Observe records what it would do while allowing traffic; Block enforces it. Start in Observe when tuning a new rule or setting.

The overall policy mode limits enforcement: policy Observe cannot become blocking merely because a signature setting says Block. Other independent controls can still reject a request. Review recorded matches and normal application use before enforcing.

[Configuration guide](policies.md)

<a id="signatures"></a>

## Managed signatures and OWASP CRS

Signatures look for known signs of attacks in requests. OWASP CRS is the bundled collection of security checks used by the Coraza inspection engine.

A policy selects one loaded managed set. Detection rules contribute matches and anomaly scores; engine helper rules keep processing and enforcement working. The rules reduce exposure to common attacks but do not replace application patches or guarantee that every attack is detected.

[Configuration guide](managed-signatures.md)

<a id="sensitivity"></a>

## Signature sensitivity

Sensitivity changes how strict the signature checks are and how much suspicious activity is needed to block. Higher settings can catch more attacks but can also flag legitimate requests.

The five presets change paranoia level plus inbound and outbound score thresholds. Standard uses paranoia 1, inbound 5 and outbound 4. Custom means the exact configured values do not match a preset. Choosing a preset changes those three settings, not body limits, mode or exclusions.

[Configuration guide](managed-signatures.md)

<a id="paranoia"></a>

## CRS paranoia level

This controls which extra signature checks are included. Higher levels include stricter checks and usually need more tuning for your application.

Levels run from 1 to 4. The level determines which detections run; anomaly thresholds determine how much accumulated evidence causes enforcement. Higher paranoia is not a guarantee of better protection for every application.

[Configuration guide](managed-signatures.md)

<a id="anomaly-score"></a>

## Anomaly score threshold

Several suspicious matches can add up to a score. A lower threshold blocks with less evidence, while a higher threshold needs more evidence.

Inbound scores describe the request sent to your application; outbound scores describe inspected responses. Scores are not probabilities or percentages. Their effect depends on the selected rules, sensitivity and Observe/Block modes. Sparse curated sets may need different thresholds from the full bundle.

[Configuration guide](managed-signatures.md)

<a id="curated-set"></a>

## Curated signature set

A curated set is a saved selection of checks from a loaded signature bundle. Use it when you want a smaller, application-specific collection.

Required engine helpers are retained automatically. Saved sets are immutable and policies keep referencing their chosen set until explicitly changed. A small selection can miss attacks or fail to reach thresholds designed for the full bundle; test both legitimate and attack traffic in Observe.

[Configuration guide](managed-signatures.md)

<a id="exceptions"></a>

## Signature exceptions

An exception skips selected security checks for a specific path, parameter or client network. Keep exceptions narrow so other traffic stays protected.

Scoped conditions combine: a path and client network must both match when both are supplied. Parameter exclusions skip only those request arguments for the selected rules. Global exclusions disable a selected rule throughout this policy. Changes take effect only when the policy is saved.

[Configuration guide](security-tuning.md)

<a id="body-inspection"></a>

## Body inspection limits

The body is the content sent with a request, such as a form or file upload. The limit sets how much Aegis inspects, not necessarily how much your application can receive.

Managed inspection accepts limits from 4 KiB to 1 MiB. Reject blocks oversized requests with 413 when enforcing; prefix inspection forwards the entire body but leaves the remainder uninspected. Observe forwards oversized requests with incomplete-inspection metadata. Invalid structured input or other checks can still reject a request.

[Configuration guide](body-inspection.md)

<a id="response-inspection"></a>

## Response inspection

This checks content coming back from your application for selected security signatures. It can add delay when Aegis must inspect a response before releasing it.

Web profiles buffer supported text responses up to the configured limit. SSE/streaming profiles inspect bounded windows after delivery, so bytes already sent cannot be recalled. WebSocket frames, binary gRPC and unsupported content types are not body-inspected. Response inspection starts off and is capped by policy/signature Observe mode.

[Configuration guide](body-inspection.md)

<a id="flood"></a>

## HTTP flood protection

Flood protection limits how quickly a client or application can receive requests. It helps control repeated requests that could overwhelm your service.

Choose a sustained requests-per-second budget and a burst allowance. Budgets belong to an application and its selected policy. Local counters are separate on each replica; shared counters coordinate budgets across replicas. This does not provide network-layer DDoS protection.

[Configuration guide](shared-rate-state.md)

<a id="request-rate"></a>

## Requests per second

This is the sustained number of requests allowed each second. A client limit applies to one resolved client IP; an application limit combines its clients under the selected policy.

The client and application budgets both apply when flood protection is active. Clients sharing one public IP may share the client budget. Start with normal measured traffic and allow room for legitimate bursts. Logarithmic sliders cover small and large budgets; exact fields remain available.

[Configuration guide](shared-rate-state.md)

<a id="burst"></a>

## Burst allowance

A burst lets a client send a short spike above its usual request rate. After that allowance is used, requests must stay within the sustained rate as the budget refills.

Set burst at least as high as the requests-per-second value. Bigger bursts accommodate page loads and short API spikes, but allow more traffic through at once. The bot-frequency burst is a suspicion signal; flood bursts are enforcement budgets.

[Configuration guide](shared-rate-state.md)

<a id="bot"></a>

## Bot detection and CAPTCHA

Bot checks look for signs that traffic is automated. Aegis can ask suspicious clients to complete a self-hosted CAPTCHA instead of challenging every visitor.

The suspicion score combines several imperfect signals and is spoofable. In Observe, the decision is recorded; in Block, enabled selective verification challenges clients reaching its threshold. CAPTCHA success grants limited bot clearance, not a bypass of flood, location or signature protection.

[Configuration guide](bot-protection.md)

<a id="bot-score"></a>

## Bot suspicion threshold

This is the suspicion score needed before Aegis asks for a CAPTCHA. Lower values challenge sooner; higher values need stronger signs of automation.

The score is not a percentage chance of being a bot. Selective CAPTCHA must be enabled, and enforcement is limited by the application or policy mode. Observe first, especially for APIs and legitimate automated clients.

[Configuration guide](bot-protection.md)

<a id="clearance"></a>

## Bot clearance duration

This is how long a successful CAPTCHA lets that client avoid another bot challenge for the application. Other security checks continue to run.

Clearance is bounded to the application and client and requires HTTPS. It is not a login session, proof of permanent trust, or permission to bypass flood protection. Shorter duration asks for verification more often; longer duration reduces repeated challenges.

[Configuration guide](bot-protection.md)

<a id="cidr"></a>

## IP addresses, CIDRs and subnets

A CIDR describes a group of IP addresses, such as 192.168.1.0/24 for a typical local subnet. Use one IP when you mean one device, or a subnet when you mean a whole network.

The suffix describes how much of the address identifies the network; a larger suffix generally means a smaller range. Aegis normalizes saved address objects. Adding a range does not automatically make it trusted: the block, allow, exemption or policy-assignment setting determines its effect.

[Configuration guide](address-objects.md)

<a id="address-object"></a>

## IP address objects and groups

An address object gives one IP or network a readable name. A group combines objects so you can reuse the same selection in several places.

Objects accept individual IPv4/IPv6 addresses, CIDRs and supported subnet-mask notation. Their role matters: trusted proxies may supply identity headers; allow entries may bypass checks; block entries deny traffic. The Local flag changes map display only.

[Configuration guide](address-objects.md)

<a id="allow-bypass"></a>

## Allow-list bypass

An allow entry can skip Geo checks only, or skip all WAF protections for matching clients. Choose the smaller bypass unless the client truly needs full trust.

CIDR block entries take precedence over overlapping allow entries. Geo-only bypass retains signatures, bot checks and flood protection. Full bypass skips those protections while routing, TLS and logging continue. A reliable resolved client identity is required.

[Configuration guide](headers-and-cidrs.md)

<a id="component-exemptions"></a>

## Component protection exemptions

Exemptions apply only to the selected protection component. Flood exemptions skip both client and whole-application flood budgets; anti-bot exemptions skip bot detection and selective CAPTCHA.

IP addresses, CIDRs and selected address objects or groups match the reliably resolved client IP. Flood-exempt requests consume neither flood budget. Anti-bot exemptions skip both the basic bot detector and selective CAPTCHA. Other protection components and declarative WAF rules remain active, and requests remain visible in logs and traffic totals. These exemptions do not grant Geo-only or full WAF allow-list bypass.

[Configuration guide](headers-and-cidrs.md)

<a id="geo"></a>

## Geo blocking

Geo blocking uses an IP address’s approximate country to allow or block traffic. It can help narrow access, but VPNs and proxies can make a visitor appear somewhere else.

Lookups use a locally loaded database rather than a remote query for each request. CIDR block and allow decisions happen first. Choose whether selected countries are allowed or blocked, and separately decide what happens when location is unknown.

[Configuration guide](geolocation.md)

<a id="trusted-proxy"></a>

## Trusted proxies and client identity

If Aegis sits behind another proxy, it needs to know which proxy can report the visitor’s real IP. Trust only the devices that actually connect to Aegis and sanitize those headers.

Untrusted connections use their socket IP; they cannot select an internal policy merely by sending a forwarding header. A trusted proxy is allowed to supply identity information, not automatically allowed to bypass protection. Configure trust per proxy host before using client-based policies or Geo decisions.

[Configuration guide](headers-and-cidrs.md)

<a id="forwarded-headers"></a>

## Forwarded headers

These headers tell your application about the original visitor and connection, such as the visitor IP and whether they used HTTPS. Aegis rebuilds them from the identity it has verified.

Forwarded client headers include X-Forwarded-For, X-Real-IP, host, protocol and port. Client-supplied identity headers from untrusted peers are discarded. Custom request and response headers are a separate feature; avoid putting secrets into values unnecessarily.

[Configuration guide](headers-and-cidrs.md)

<a id="priority"></a>

## Policy assignment priority

Priority decides which matching client policy is used first. A smaller number wins; the default policy handles clients that match none of the specific ranges.

Aegis does not choose the most specific CIDR automatically: configured priority wins. Applications with client-specific policies need a default. Selecting a policy does not itself allow traffic; the chosen policy’s protection settings still apply.

[Configuration guide](policies.md)

<a id="community"></a>

## Community mitigations

These are focused rules supplied by the community feed for particular vulnerabilities or attack patterns. Select all current rules or only the ones suitable for your applications.

Review each rule’s coverage, limits and compatibility before enforcing. Some mitigation rules intentionally reject legitimate request types. Saved policies keep pinned copies; syncing the feed downloads updates but does not silently change a published policy. Refresh selected snapshots and save to adopt updates.

[Configuration guide](rule-feeds.md)

<a id="rule-groups"></a>

## Rule groups

A rule group collects selected custom rules inside a policy. You can narrow the group to a path or HTTP methods so it protects only the relevant part of an application.

Group path and method conditions combine with each rule’s own conditions. Published groups contain frozen copies, so library edits do not change live protection until explicitly refreshed and saved. Common method chips retain custom methods entered in the exact list.

[Configuration guide](policies.md)

<a id="feed"></a>

## Rule feeds and pinned snapshots

A feed is a subscription that downloads available rule definitions. A pinned snapshot is the saved version a policy keeps using until you explicitly refresh it.

Automatic and manual sync update the local catalogue. They do not activate new rules, select future additions or silently replace published policy snapshots. Policies choose which mitigations apply and when to adopt downloaded revisions.

[Configuration guide](rule-feeds.md)

<a id="proxy-host"></a>

## Proxy host and upstream

A proxy host is the application address visitors use. Its upstream is the server Aegis forwards accepted requests to.

The hostname selects the configured application; routing and upstream connection settings determine where the request goes. An HTTPS connection from the visitor to Aegis and an HTTPS connection from Aegis to the upstream are separate connections with separate certificate trust requirements.

[Configuration guide](getting-started.md)

<a id="endpoint-type"></a>

## Website, API and streaming endpoints

Choose the kind of service behind the proxy: a website, an API used by software, or a streaming/SSE endpoint that sends results gradually. This helps Aegis handle inspection and delivery appropriately.

SSE means Server-Sent Events, often used for live updates and model output. Streaming profiles send chunks promptly and inspect supported response windows after delivery; previously sent data cannot be taken back. Binary gRPC and WebSocket frames are not response-body inspected.

[Configuration guide](body-inspection.md)

<a id="tls"></a>

## TLS and HTTPS certificates

HTTPS encrypts the connection and uses a certificate to prove which hostname the server represents. A certificate must cover the hostname visitors use and be currently valid.

Aegis terminates visitor TLS with its selected certificate. Upstream TLS is separate and should also be verified. Certificates are public identity documents; private keys are secrets stored encrypted using an external encryption key.

[Configuration guide](certificates.md)

<a id="acme"></a>

## ACME certificate automation

ACME is the standard Aegis uses to request and renew HTTPS certificates automatically. You provide the domains and prove you control them.

Configure a certificate authority account and accept its terms. HTTP-01 proves control through a public HTTP challenge; DNS-01 proves it by creating a DNS record through a supported provider. Existing valid certificates remain active when a renewal fails.

[Configuration guide](certificates.md)

<a id="dns-challenge"></a>

## DNS verification (DNS-01)

DNS verification proves domain ownership by creating a temporary DNS record. With a Cloudflare token, Aegis can handle that automatically without an inbound port-80 challenge.

The token needs the documented Zone Read and DNS Edit permissions for the zones being managed. It is stored encrypted for renewal and never returned by ordinary read APIs. DNS propagation takes time, and failures appear in certificate job status.

[Configuration guide](cloudflare.md)

<a id="http-challenge"></a>

## HTTP verification (HTTP-01)

HTTP verification proves domain ownership by serving a temporary challenge on your domain. The certificate authority must be able to reach it publicly on port 80.

DNS for each requested hostname must route the challenge to Aegis, directly or through a forwarding load balancer. Every replica can answer stored challenges. Use supported DNS verification when public port 80 cannot be routed to Aegis.

[Configuration guide](certificates.md)

<a id="staging"></a>

## Certificate staging and production

Staging is a practice certificate service that avoids spending production issuance limits. Its certificates are for testing and are not trusted by normal browsers.

Use staging to verify account registration, DNS/HTTP validation and renewal flow, then use a production directory for publicly trusted certificates. Changing a directory does not turn an already issued staging certificate into a trusted production certificate.

[Configuration guide](certificates.md)

<a id="pem"></a>

## PEM chains and private keys

PEM is the text format used to upload certificates and keys, including the BEGIN and END lines. A chain includes the server certificate and the intermediate certificates needed to verify it.

The private key must match the certificate, and the certificate must be valid for the assigned hostnames. Aegis validates uploads before replacing the active certificate, so failed replacements keep the previous working certificate. Never share the private key in logs, screenshots or public issues.

[Configuration guide](certificates.md)

<a id="hsts"></a>

## HSTS browser protection

HSTS tells browsers to use HTTPS for this hostname for a set time. Enable it only after HTTPS works reliably for that hostname.

It does not trust upstream self-signed certificates or configure upstream TLS. Include subdomains only when all of them support HTTPS. Turning the switch off does not remove a policy already cached by browsers; a max age of zero clears this host’s policy when received over trusted HTTPS.

[Configuration guide](headers-and-cidrs.md)

<a id="mcp"></a>

## MCP agent access

MCP is the interface an external AI agent can use to inspect and manage Aegis. Aegis remains the WAF; you choose the agent and its workflow.

Enable access deliberately and issue scoped, source-restricted keys. An agent can act only within its granted permissions. MCP does not automatically start an idle agent; configurable alert destinations can wake an external automation receiver. Account and MCP-key creation remain outside the agent management tools.

[Configuration guide](agent-access.md)

<a id="api-scope"></a>

## API key scopes and allowed sources

Scopes limit which actions a key may perform. Allowed source addresses limit where that key may connect from; both restrictions must be satisfied.

Grant the smallest useful permissions and use separate keys for separate agents or monitoring systems. The secret is shown only when created. Source restrictions use the actual connecting peer address; forwarded headers do not grant access, and a key is not an administrator account or permission to create additional keys.

[Configuration guide](agent-access.md)

<a id="simulation"></a>

## Rule simulation and replay

Simulation tries a proposed change against available recorded traffic before it goes live. It helps you spot likely false positives, but cannot prove that a rule is safe for every future request.

Agent protection mutations require a fresh simulation tied to the exact proposed change. Replay depends on retained, bounded and redacted evidence, so incomplete samples limit what can be evaluated. Review the result and the rule’s scope before applying.

[Configuration guide](agent-access.md)

<a id="evidence"></a>

## Request evidence and redaction

Evidence is a saved sample used to investigate or replay a request. Redaction tries to remove sensitive values before samples are retained.

Capture is explicitly configured, sampled, capped and subject to retention. Not every request has a body sample, and a sample may be truncated or incomplete. Paths, headers and parameters can still contain personal information; review capture allowlists, retention and export settings.

[Configuration guide](request-investigation.md)

<a id="webhook"></a>

## Webhooks and alert destinations

A webhook sends an alert to a URL that you configure, so another system can notify a person or start an investigation. It does not automatically give the receiver permission to change Aegis.

Choose a supported destination or an automation webhook and test delivery. A signed webhook lets the receiver verify the sender and message. Alert evaluation, delivery retries and an external agent’s behavior are separate steps; inspect delivery history when a notification does not arrive.

[Configuration guide](alerts.md)

<a id="metrics"></a>

## Prometheus metrics

Metrics are numeric measurements that a monitoring system can collect over time, such as request counts and inspection duration. Prometheus is one common tool for collecting them.

The management metrics endpoint requires authentication. Measurements are replica-local: collect from each replica and combine them in your monitoring system. Metrics do not include full request bodies and are separate from access logs and audit events.

[Configuration guide](observability.md)

<a id="replicas"></a>

## Replicas and shared rate state

A replica is another running copy of Aegis. Configuration is shared through PostgreSQL, while the rate-state setting chooses whether live request counters are local or shared.

Local mode needs no extra service but each replica has its own budget. Optional Redis/Dragonfly counters coordinate flood budgets and bot request-frequency signals across replicas. Shared-counter failure does not silently fall back to local enforcement.

[Configuration guide](shared-rate-state.md)

<a id="audit"></a>

## Audit events and access logs

Access logs describe requests and their outcomes. Audit events record administrative actions, such as changing a policy or certificate.

Request details identify the application, response source and available rule matches. Evidence samples are a separate opt-in feature. Administrative audit records contain operation metadata rather than passwords, stored private keys or request samples.

[Configuration guide](logging.md)

<a id="local-location"></a>

## Local traffic map location

A Local address object marks traffic whose map display should use the gateway’s configured public-IP location. It changes the map, not the actual client IP or access decision.

Configure the gateway public IP and load a location database first. Automatic IP detection finds the replica’s outbound public IP, which can differ from the inbound address behind NAT or a VPN. Geo blocking always uses the actual client IP rather than this display location.

[Configuration guide](geolocation.md)

<a id="bootstrap"></a>

## Bootstrap secret

This is the one-time setup secret created when Aegis was deployed. It proves you are allowed to create the first administrator account.

Obtain it from the person who deployed Aegis or the deployment secret file. It is separate from your administrator password and is not a default credential. After the first administrator exists, use the account login instead; do not share bootstrap values in screenshots or support requests.

[Configuration guide](deployment.md)

<a id="upstream-tls"></a>

## Upstream TLS trust

This lets Aegis accept a selected private CA or backend certificate for this proxy host. It keeps hostname and expiration checks enabled.

Prefer the private CA certificate so backend renewals keep working. Trusting a server certificate pins that exact certificate and requires updating it when it rotates. A server-name override selects the expected TLS identity when connecting to an IP; it does not change the HTTP Host header. Test upstream uses the current unsaved values, sends a GET without credentials, does not follow redirects, and never disables certificate verification. When Test upstream finds an unknown issuer, review the displayed subject, issuer, expiry and SHA-256 fingerprint before checking Trust a private upstream certificate. The checkbox copies that public certificate into the unsaved trust setting; it never turns off verification. Name-mismatched or expired certificates are not offered for this shortcut.

[Configuration guide](upstreams.md)

<a id="http-methods"></a>

## Allowed HTTP methods

An HTTP method describes an operation: GET reads, POST sends, PUT/PATCH update, and DELETE removes. Choose which operations your API should accept.

Automatic Website methods follow the CRS source; API and SSE additionally allow PUT, PATCH and DELETE. Explicit policy methods override these defaults. The CRS method-enforcement rule must remain selected for this setting to enforce; excluding that rule disables its check. TRACE and CONNECT are excluded from automatic defaults. Methods are not application authentication or permission to access particular records.

[Configuration guide](body-inspection.md)

<a id="api-start"></a>

## API starting settings

This fills the policy form with starting values for API or AI traffic in Observe mode. You can review matches before allowing those checks to block requests.

The button chooses Standard sensitivity, common API methods, a 1 MiB request limit, an 8 KiB policy stream window, response inspection Off, and bot/empty-User-Agent checks Off. It preserves the selected rule set, custom/community rules, assignments, flood budgets and connection limits. Nothing applies until Save policy. SQL/HTML in prompts can match generic website signatures, so this is not automatic prompt-injection protection.

[Configuration guide](policies.md)

<a id="connection-limits"></a>

## Connection and stream limits

Concurrent means requests running at the same time, including open streams. These limits cap simultaneous requests and how long they can run or wait without progress.

Budgets belong to the application, selected policy and replica, even when request-rate counters use Redis. Block enforces, Observe records exceedances, Off disables them, and full WAF bypass skips them. A client cap uses the resolved IP and can include multiple users behind one public IP. Existing connections retain their admission settings across reloads. Limits before headers can return 429 or 504; a stream already delivering data can be cut off with its original status. WebSocket frame activity is not used for the idle timer.

[Configuration guide](body-inspection.md)

<a id="stream-window"></a>

## Streaming inspection window

Aegis checks a stream in small, overlapping chunks of text. A larger window sees more text at once and uses more processing and memory.

The policy window ranges from 4–64 KiB and is capped by its response-body limit. New policies use an 8 KiB override. Existing policies without an override retain the legacy host window until explicitly changed. Inspection happens after delivery: Block can stop future chunks but cannot recall bytes already sent. Scores reset for each window and this does not understand AI prompts or MCP tool semantics.

[Configuration guide](body-inspection.md)
