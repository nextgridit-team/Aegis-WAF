import { esc, heading, field, check, table, dateTime } from "./ui";
type Channel = {
  id: number;
  name: string;
  provider: string;
  enabled: boolean;
  revision: number;
  has_config: boolean;
};
type Rule = {
  id: number;
  revision: number;
  name: string;
  enabled: boolean;
  kind: string;
  site_id: number;
  threshold: number;
  window_minutes: number;
  cooldown_minutes: number;
  channel_ids: number[];
};
type Alert = {
  id: number;
  rule_id: number;
  at: string;
  kind: string;
  site_id: number;
  title: string;
  count: number;
  window_start: string;
  window_end: string;
  acknowledged_at: string | null;
  acknowledged_by: string;
};
type Delivery = {
  id: number;
  alert_id: number;
  channel_id: number;
  status: string;
  attempts: number;
  error: string;
  next_attempt: string;
};
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  notice: (message: string, error?: boolean) => void;
  handleError: (error: unknown) => Promise<void>;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
};
const providers: Record<string, string> = {
  automation: "AI / automation webhook (signed)",
  webhook: "Generic webhook",
  slack: "Slack incoming webhook",
  discord: "Discord webhook",
  gotify: "Gotify",
  ntfy: "ntfy",
  apprise: "Apprise API bridge",
};
const kinds: Record<string, string> = {
  blocked_volume: "Blocked request volume",
  upstream_errors: "Upstream / gateway failures",
  certificate_expiry: "Certificate expiration",
  acme_failure: "ACME renewal / issuance failures",
};
export function makeAlertsPage(c: Context) {
  let serial = 0,
    tab = "inbox";
  async function render(view: HTMLElement) {
    const stamp = ++serial;
    const [channels, rules, alerts, deliveries, sites] = await Promise.all([
      c.api<Channel[]>("/notification-channels"),
      c.api<Rule[]>("/alert-rules"),
      c.api<Alert[]>("/alerts"),
      c.api<Delivery[]>("/alert-deliveries"),
      c.api<{ id: number; name: string }[]>("/sites"),
    ]);
    if (stamp !== serial || !view.isConnected) return;
    const siteName = (id: number) =>
      id
        ? sites.find((s) => s.id === id)?.name || `Removed application #${id}`
        : "All applications";
    const buttons = (kind: string, id: number) =>
      `<button class="secondary compact" data-alert-edit="${kind}" data-id="${id}">Edit</button> <button class="danger compact" data-alert-delete="${kind}" data-id="${id}">Delete</button>`;
    let content = "";
    if (tab === "inbox")
      content = `<section class="dashboard-panel"><h2>Alert inbox</h2><p>Alerts summarize recorded traffic or certificate state. Acknowledgement records investigation; it does not change protection.</p>${table(
        ["Alert", "Application", "Count", "Time", "Status", "Actions"],
        alerts.map((a) => [
          `${esc(a.title)}<small>#${a.id} · ${esc(kinds[a.kind] || a.kind)}</small>`,
          esc(siteName(a.site_id)),
          esc(a.count),
          esc(dateTime(a.at)),
          a.acknowledged_at
            ? `Acknowledged<small>${esc(a.acknowledged_by)}</small>`
            : "Needs review",
          `<button class="secondary compact" data-alert-details="${a.id}">Details</button> ${a.acknowledged_at ? "" : `<button class="secondary compact" data-alert-ack="${a.id}">Acknowledge</button>`}`,
        ]),
        "Alerts",
      )}</section>`;
    if (tab === "rules")
      content = `<section class="dashboard-panel"><div class="section-heading"><h2>Trigger rules</h2><button class="primary" data-alert-new="rule">Add alert rule</button></div><p>Scope a trigger to an application or the whole gateway. Thresholds and cooldowns group activity into actionable alerts.</p>${table(
        [
          "Name",
          "Trigger",
          "Application",
          "Threshold",
          "Destinations",
          "Actions",
        ],
        rules.map((r) => [
          `${esc(r.name)}<small>${r.enabled ? "Enabled" : "Disabled"}</small>`,
          esc(kinds[r.kind]),
          esc(siteName(r.site_id)),
          `${r.threshold}${r.kind === "certificate_expiry" ? " days" : ` in ${r.window_minutes} min`}<small>${r.cooldown_minutes} min cooldown</small>`,
          r.channel_ids
            .map((id) =>
              esc(
                channels.find((c) => c.id === id)?.name ||
                  "Removed destination",
              ),
            )
            .join(", ") || "Inbox only",
          buttons("rule", r.id),
        ]),
        "Alert rules",
      )}</section>`;
    if (tab === "destinations")
      content = `<section class="dashboard-panel"><div class="section-heading"><h2>Notification destinations</h2><button class="primary" data-alert-new="channel">Add destination</button></div><p>Send a test after saving. URLs and secrets are encrypted and never returned by read APIs. No AI provider is selected by Aegis.</p>${table(
        ["Name", "Provider", "Status", "Actions"],
        channels.map((ch) => [
          esc(ch.name),
          esc(providers[ch.provider]),
          ch.enabled ? "Enabled" : "Disabled",
          `${buttons("channel", ch.id)} <button class="secondary compact" data-alert-test="${ch.id}">Send test</button>`,
        ]),
        "Notification destinations",
      )}</section><section class="dashboard-panel"><h2>Delivery history</h2><p>Retries use backoff, up to five attempts. Delivery is at least once; receivers should deduplicate by alert ID. Disabled destinations pause pending deliveries.</p>${table(
        ["Alert", "Destination", "Status", "Attempts", "Details"],
        deliveries.map((d) => [
          `#${d.alert_id}`,
          esc(
            channels.find((ch) => ch.id === d.channel_id)?.name ||
              "Removed destination",
          ),
          esc(d.status),
          esc(d.attempts),
          esc(d.error || (d.status === "sent" ? "Delivered" : "Queued")),
        ]),
        "Notification deliveries",
      )}</section>`;
    view.innerHTML =
      heading(
        "Alerts",
        "Send actionable notifications to your tools, your team or your own AI agent.",
      ) +
      `<div class="form-actions" role="group" aria-label="Alert views">${[
        [
          "inbox",
          `Inbox · ${alerts.filter((a) => !a.acknowledged_at).length} need review`,
        ],
        ["rules", "Trigger rules"],
        ["destinations", "Destinations"],
      ]
        .map(
          ([key, label]) =>
            `<button class="${tab === key ? "primary" : "secondary"}" data-alert-tab="${key}" aria-pressed="${tab === key}">${esc(label)}</button>`,
        )
        .join(
          "",
        )}<button class="secondary" data-alert-refresh>Refresh</button></div>${content}<section class="info-panel"><h3>Wake your agent, investigate through MCP</h3><p>Configure an AI / automation webhook with your receiver URL and a shared signing secret. Your receiver starts its chosen agent, which reads this inbox through scoped MCP operations and acknowledges reviewed alerts. MCP alone does not start an AI workflow. Never treat traffic content as agent instructions.</p><p>Evaluation runs about every 10 seconds while PostgreSQL is available. Traffic alerts depend on best-effort access logs. History retains 30 days and at most 1000 alerts. No destinations or rules are enabled automatically.</p></section>`;
    const run = (fn: () => Promise<unknown>) => async (e: Event) => {
      const button = e.currentTarget as HTMLButtonElement;
      button.disabled = true;
      try {
        await fn();
      } catch (error) {
        await c.handleError(error);
      } finally {
        button.disabled = false;
      }
    };
    view.querySelectorAll<HTMLButtonElement>("[data-alert-tab]").forEach(
      (b) =>
        (b.onclick = run(async () => {
          tab = b.dataset.alertTab!;
          await render(view);
        })),
    );
    view.querySelector<HTMLButtonElement>("[data-alert-refresh]")!.onclick =
      run(() => render(view));
    view.querySelectorAll<HTMLButtonElement>("[data-alert-ack]").forEach(
      (b) =>
        (b.onclick = run(async () => {
          await c.api(`/alerts/${b.dataset.alertAck}/acknowledge`, "POST", {});
          await render(view);
        })),
    );
    view.querySelectorAll<HTMLButtonElement>("[data-alert-test]").forEach(
      (b) =>
        (b.onclick = run(async () => {
          await c.api(
            `/notification-channels/${b.dataset.alertTest}/test`,
            "POST",
            {},
          );
          c.notice("Test notification delivered.");
          await render(view);
        })),
    );
    view.querySelectorAll<HTMLButtonElement>("[data-alert-delete]").forEach(
      (b) =>
        (b.onclick = run(async () => {
          const kind = b.dataset.alertDelete!;
          await c.api(
            `/${kind === "rule" ? "alert-rules" : "notification-channels"}/${b.dataset.id}`,
            "DELETE",
            {},
          );
          await render(view);
        })),
    );
    view.querySelectorAll<HTMLButtonElement>("[data-alert-details]").forEach(
      (b) =>
        (b.onclick = () => {
          const a = alerts.find(
            (a) => a.id === Number(b.dataset.alertDetails),
          )!;
          c.openEditor(
            "Alert details",
            `<p>${esc(a.title)}</p><dl><dt>Alert / trigger ID</dt><dd>#${a.id} / #${a.rule_id}</dd><dt>Reason</dt><dd>${esc(kinds[a.kind])}</dd><dt>Application</dt><dd>${esc(siteName(a.site_id))}</dd><dt>Count</dt><dd>${a.count}</dd><dt>Window</dt><dd>${esc(dateTime(a.window_start))} – ${esc(dateTime(a.window_end))}</dd></dl><p>Use Activity and request details for individual decisions, signatures and available evidence. This alert contains summary metadata, not request bodies.</p><a class="secondary" href="#activity">Open Activity</a>`,
          );
        }),
    );
    const actions = (label: string) =>
      `<div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="${label}">${label}</button></div>`;
    function editChannel(ch?: Channel) {
      c.openEditor(
        ch ? "Edit destination" : "Add destination",
        `<form id="alert-channel-form">${field("name", "Name", ch?.name || "", "text", 'required maxlength="120"')}<label class="field" for="alert-provider">Provider</label><select id="alert-provider" name="provider">${Object.entries(
          providers,
        )
          .map(
            ([id, name]) =>
              `<option value="${id}" ${id === (ch?.provider || "automation") ? "selected" : ""}>${name}</option>`,
          )
          .join(
            "",
          )}</select>${field("url", "Destination URL (write only)", "", "url", `${ch ? "" : "required"} maxlength="2048" autocomplete="off" placeholder="${ch ? "Stored · leave blank to keep settings" : "https://receiver.example.com/aegis"}"`)}${field("secret", "Signing secret / token (write only)", "", "password", 'maxlength="4096" autocomplete="new-password"')}<small>AI/automation requires a signing secret of at least 32 bytes. Webhook uses HMAC when a secret is supplied. Gotify uses its application token; ntfy/Apprise use Bearer tokens. Slack/Discord credentials belong in their webhook URL. On edit, leave URL blank to preserve all stored settings; supplying it replaces URL, token and private-network choice together.</small>${check("allow_private", "Allow private-network destination (HTTP allowed only to private/loopback addresses)", false)}${check("enabled", "Enable destination", ch?.enabled ?? true)}${actions("Save destination")}</form>`,
      );
      c.formHandler("alert-channel-form", async (f) => {
        const url = String(f.get("url") || "").trim();
        if (!url && (String(f.get("secret") || "") || f.has("allow_private")))
          throw new Error(
            "Supply the destination URL when replacing its settings.",
          );
        await c.api(
          ch ? `/notification-channels/${ch.id}` : "/notification-channels",
          ch ? "PUT" : "POST",
          {
            name: f.get("name"),
            provider: f.get("provider"),
            enabled: f.has("enabled"),
            revision: ch?.revision || 0,
            ...(url
              ? {
                  config: {
                    url,
                    secret: f.get("secret"),
                    allow_private: f.has("allow_private"),
                  },
                }
              : {}),
          },
        );
        c.closeEditor();
        await render(view);
      });
    }
    function editRule(rule?: Rule) {
      c.openEditor(
        rule ? "Edit alert rule" : "Add alert rule",
        `<form id="alert-rule-form">${field("name", "Name", rule?.name || "", "text", 'required maxlength="120"')}<label class="field" for="alert-kind">Trigger</label><select id="alert-kind" name="kind">${Object.entries(
          kinds,
        )
          .map(
            ([id, name]) =>
              `<option value="${id}" ${id === (rule?.kind || "blocked_volume") ? "selected" : ""}>${name}</option>`,
          )
          .join(
            "",
          )}</select><label class="field" for="alert-site">Application</label><select id="alert-site" name="site_id"><option value="0">All applications</option>${sites.map((s) => `<option value="${s.id}" ${s.id === rule?.site_id ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select>${field("threshold", "Threshold (count; days for certificate expiration)", String(rule?.threshold || 10), "number", 'required min="1" max="1000000"')}${field("window_minutes", "Traffic window (minutes)", String(rule?.window_minutes || 5), "number", 'required min="1" max="60"')}${field("cooldown_minutes", "Notification cooldown (minutes)", String(rule?.cooldown_minutes || 15), "number", 'required min="1" max="10080"')}<small>Certificate expiration uses threshold days (1–90) and fires when any scoped certificate expires within that period. ACME counts currently retrying jobs. Traffic windows apply to volume triggers; cooldown applies to every trigger. New/updated rules evaluate recorded events from their saved start time.</small><fieldset><legend>Destinations</legend>${channels.map((ch) => check(`channel_${ch.id}`, ch.name, rule?.channel_ids.includes(ch.id) || false)).join("") || "<p>Create destinations to send notifications, or retain alerts in the inbox only.</p>"}</fieldset>${check("enabled", "Enable alert rule", rule?.enabled ?? true)}${actions("Save alert rule")}</form>`,
      );
      c.formHandler("alert-rule-form", async (f) => {
        await c.api(
          rule ? `/alert-rules/${rule.id}` : "/alert-rules",
          rule ? "PUT" : "POST",
          {
            name: f.get("name"),
            kind: f.get("kind"),
            site_id: Number(f.get("site_id")),
            threshold: Number(f.get("threshold")),
            window_minutes: Number(f.get("window_minutes")),
            cooldown_minutes: Number(f.get("cooldown_minutes")),
            channel_ids: channels
              .filter((ch) => f.has(`channel_${ch.id}`))
              .map((ch) => ch.id),
            enabled: f.has("enabled"),
            revision: rule?.revision || 0,
          },
        );
        c.closeEditor();
        await render(view);
      });
    }
    view
      .querySelectorAll<HTMLButtonElement>("[data-alert-new]")
      .forEach(
        (b) =>
          (b.onclick = () =>
            b.dataset.alertNew === "rule" ? editRule() : editChannel()),
      );
    view
      .querySelectorAll<HTMLButtonElement>("[data-alert-edit]")
      .forEach(
        (b) =>
          (b.onclick = () =>
            b.dataset.alertEdit === "rule"
              ? editRule(rules.find((r) => r.id === Number(b.dataset.id)))
              : editChannel(
                  channels.find((ch) => ch.id === Number(b.dataset.id)),
                )),
      );
  }
  return { render };
}
