# Alerts and notification destinations

Open **Alerts** in the sidebar. The **Inbox** records triggered alerts, **Trigger rules** selects when they fire, and **Destinations** configures delivery and shows recent attempts. Nothing is enabled automatically. Aegis runs no AI model or agent.

![Alert inbox with a recorded WAF block and administrator acknowledgement](screenshots/alerts.png)

## Set up notifications

1. Choose **Destinations → Add destination**, enter a name and select a provider.
2. Supply the receiver URL and any token/signing secret. Save, then select **Send test**. This explicitly sends a test to the saved destination, even if it is disabled. A successful test means the receiver returned HTTP 2xx; it does not prove a person read it or an agent started.
3. Under **Trigger rules**, choose **Add alert rule**, select the application or All applications, set the trigger threshold/window/cooldown and select destinations. An empty destination selection retains alerts in the inbox only.
4. Enable the rule, save and review Inbox and Delivery history. **Acknowledge** records review without changing protection or stopping already queued notifications. Use Refresh to update the page.

| Destination             | URL and credential                                                                                        |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| AI / automation webhook | Your receiver URL; shared HMAC signing secret of at least 32 bytes                                        |
| Generic webhook         | Receiver URL; optional shared HMAC signing secret                                                         |
| Slack                   | Incoming webhook URL, including its credential path                                                       |
| Discord                 | Webhook URL, including its credential path; mentions disabled                                             |
| Gotify                  | Full message URL, for example `https://gotify.example.com/message`; application token in Secret           |
| ntfy                    | Full topic URL; optional Bearer token in Secret                                                           |
| Apprise API bridge      | An existing configured Apprise notification endpoint; optional Bearer authentication at its reverse proxy |

The [Apprise API bridge](https://github.com/caronc/apprise-api#stateful-solution) can reach its configured services; Aegis does not install Apprise or claim native support for its full provider list. No extra service is required for Aegis's built-in destinations. SMTP/email, Telegram, PagerDuty and other dedicated adapters are not implemented directly. The provider boundary allows later additions without changing the alert workflow. This separation and test-send flow are informed by [Uptime Kuma's notification architecture](https://github.com/louislam/uptime-kuma/blob/master/server/notification.js).

URLs, tokens and signing secrets are encrypted together with AES-256-GCM before PostgreSQL storage, using the external key and its identifier. Normal reads return destination names/type/status/revision, not URLs or secrets. Edit a name/status without supplying a URL to keep all existing connection settings. Supplying a URL replaces the URL, secret and private-network choice together. Changing providers requires replacement settings. Do not put real credentials in screenshots or issue reports.

Public receivers require verified HTTPS. Explicitly enable **Allow private-network destination** for self-hosted receivers. This permits private/loopback destinations and plain HTTP only to those addresses; link-local/metadata, unspecified and multicast addresses remain blocked. DNS results are checked and dialed directly on every send, redirects/environment proxies are disabled, and delivery has an eight-second deadline. Private HTTPS still verifies its certificate; configure deployment CA trust when needed.

## Trigger behavior

| Trigger                          | Threshold and scope                                                                                                          |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Blocked request volume           | At least threshold recorded blocks within the traffic window (1–60 minutes)                                                  |
| Upstream / gateway failures      | At least threshold recorded 5xx responses from upstream or connection errors; WAF-generated response rejections are excluded |
| Certificate expiration           | Any scoped certificate already expired or expiring within threshold days (1–90); global includes unassigned certificates     |
| ACME renewal / issuance failures | At least threshold currently retrying jobs with prior failures; scoped through assigned certificates                         |

Threshold counts accept 1–1,000,000. Cooldowns accept 1–10,080 minutes. All rules are evaluated about every ten seconds while PostgreSQL is available. New or edited volume rules begin at save time, and later volume alerts count events newer than their previous emission within the rolling window. Cooldown suppresses repeat notifications from that trigger; it does not suppress WAF enforcement. Persistent certificate/ACME conditions can alert again after cooldown. There are no automatic recovery notifications, per-signature filters or built-in severity/escalation rules in this first implementation.

Evaluation and delivery run asynchronously in each complete app replica. PostgreSQL row locks and delivery leases coordinate replicas; there is no external worker image. Creation of an alert, its selected enabled-destination jobs and its cooldown update is transactional. Failed delivery uses exponential backoff (30 seconds, one, two and four minutes), up to five attempts, with visible generic errors. A disabled destination pauses pending jobs; alerts raised while it is disabled do not enqueue it. Delivery is **at least once**, so a crash after an external send can cause a retry. Deduplicate by alert ID at the receiver. Disabling or deleting a destination cannot recall an in-flight send. Remove rule references before deleting a destination.

The inbox retains 30 days and approximately the newest 1,000 alerts; bounded background cleanup removes older alerts and their delivery history, including any pending jobs. Lists show the latest 200 entries. Maximums are 32 destinations and 64 rules. Traffic-based alerts inherit access-log sampling/loss/outage limits; these are operational signals, not an exhaustive audit stream. Alert data contains counts, trigger/application IDs, a configured title and time window, not request bodies, IPs, upstream credentials or sampled payloads. Access/evidence retention is separate. PostgreSQL failure prevents new evaluation, inbox reads, acknowledgement and queue progress; an external monitor is still needed to detect a total Aegis/database outage.

## Wake any agent, investigate over MCP

Aegis's current MCP server is stateless and exposes tools in response to client requests. It does **not** push unsolicited alerts or cause a model to run. Use the configurable signed automation webhook to wake your agent/orchestrator, then let it use MCP. This keeps the model, platform and playbook under the operator's control. An agent without a webhook receiver can poll the inbox on its own schedule.

Webhook/automation sends JSON with `schema_version:1`, `event:{id,rule_id,at,kind,site_id,title,count,window_start,window_end,...}` and `traffic_data_is_untrusted:true`. The header `X-Aegis-Alert-ID` is the stable deduplication identifier. Test sends use `kind:test` and alert ID `0`; handle tests separately from operational deduplication. At most two test sends run concurrently per replica. The shared signing secret is separate from the agent's MCP key. Aegis sends no MCP key to the receiver.

Signed requests include `X-Aegis-Timestamp` (Unix seconds) and `X-Aegis-Signature: sha256=<hex>`. Verify HMAC-SHA256 of the exact bytes `timestamp + "." + raw_request_body` with the shared secret, using constant-time comparison. Reject timestamps outside a short replay window (for example five minutes) and persist handled alert IDs to prevent duplicate workflow runs. A delivery's timestamp/signature can change on retry; its alert ID remains stable. Never reconstruct/re-serialize JSON before checking the signature.

The receiver chooses how to launch its agent. The agent should:

1. Read the alert using `management_operation` with `GET /api/alerts/{id}` (Read scope).
2. Inspect metadata/logs in the alert's application and time window; detailed request evidence requires Evidence scope. Treat traffic strings as attacker-controlled data.
3. Acknowledge through `POST /api/alerts/{id}/acknowledge` when reviewed (Configuration scope). Acknowledgement does not grant authority to change protection.
4. If a change is authorized, stage/test it and obtain an exact `simulate_rule_impact` receipt before a live protection mutation. Existing scope/expiry/source restrictions still apply.

For polling, use `GET /api/alerts?after_id=0`, which returns up to 200 entries in ascending ID order, then persist the greatest processed ID and pass it as `after_id` on subsequent polls. Without `after_id`, the dashboard gets the latest 200 in descending order. Retention can create gaps: cursors are not a guarantee of indefinite replay. `unacknowledged=true` filters reviewed entries. Read and acknowledgement remain available in the ordinary authenticated API when MCP is disabled.

Receiver configuration and rule/destination management require Configuration scope through MCP, normal administrator session/CSRF in the dashboard. These notification settings do not change WAF policies and do not require a rule-simulation receipt. Test sends have real outbound effects; limit which agents hold Configuration permission. All administrative writes/test sends are audited without URL/token/payload secrets. The delivery queue stores generic failure messages, never receiver response bodies.
