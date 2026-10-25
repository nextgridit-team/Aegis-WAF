import { ruleTabs } from "./rule-tabs";
export type RuleSpec = {
  schema_version: number;
  name: string;
  scope: { site_id: number; path_prefix?: string };
  all: { field: string; key?: string; op: string; value: string | string[] }[];
  action: "observe" | "block";
  ttl_seconds: number;
  evidence_ids?: string[];
};
type Rule = {
  id: number;
  site_id: number;
  spec: RuleSpec;
  enabled: boolean;
  expires_at: string | null;
  revision: number;
  status: string;
};
type Settings = {
  redact_patterns?: string[];
  enabled: boolean;
  capture_path: boolean;
  security_events_disabled?: boolean;
  security_samples?: boolean;
  query_keys: string[];
  header_keys: string[];
  json_body_keys: string[];
  sample_every: number;
  max_per_minute: number;
  retention_hours: number;
};
type Fact = { state: string; values?: string[] };
type Event = {
  id: string;
  site_id: number;
  at: string;
  expires_at: string;
  data: {
    schema_version: number;
    facts: Record<string, Fact>;
    body_length: number;
    content_type?: string;
    rule_results: { rule_id: number; action: string; result: string }[];
  };
};
type Site = { id: number; name: string; hostnames: string[] };
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  sites: () => Site[];
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (f: FormData) => Promise<void>) => void;
  refresh: () => Promise<void>;
  notice: (message: string, error?: boolean) => void;
};
const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const btn = (
  action: string,
  label: string,
  style = "secondary compact",
  id?: number | string,
) =>
  `<button type="button" class="${style}" data-action="${action}" ${id !== undefined ? `data-id="${esc(id)}"` : ""}>${label}</button>`;
const field = (
  name: string,
  label: string,
  value = "",
  type = "text",
  attrs = "",
) =>
  `<label class="field">${label}<input name="${name}" value="${esc(value)}" type="${type}" ${attrs}></label>`;
const checkbox = (name: string, label: string, checked = false) =>
  `<label class="check"><input name="${name}" type="checkbox" ${checked ? "checked" : ""}><span>${label}</span></label>`;
const actions = (label: string) =>
  `<div class="form-actions">${btn("cancel", "Cancel", "secondary")}<button class="primary" type="submit" data-label="${label}">${label}</button></div>`;
const badge = (value: string) =>
  `<span class="badge ${value === "block" ? "danger" : value === "observe" ? "info" : value === "enabled" ? "success" : "neutral"}">${esc(value)}</span>`;
const table = (columns: string[], rows: string[][], label: string) =>
  `<div class="table-wrap" tabindex="0" role="region" aria-label="${label}"><table><thead><tr>${columns.map((h) => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
const heading = (title: string, text: string, buttons: string) =>
  `<div class="page-heading"><div><h1>${title}</h1><p>${text}</p></div><div class="heading-actions">${buttons}</div></div>`;
const empty = (title: string, text: string) =>
  `<section class="empty-state"><h2>${title}</h2><p>${text}</p></section>`;
const defaults = (): Settings => ({
  enabled: false,
  capture_path: false,
  query_keys: [],
  header_keys: [],
  json_body_keys: [],
  sample_every: 1,
  max_per_minute: 60,
  retention_hours: 24,
});
const csv = (v: FormDataEntryValue | null) =>
  String(v || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
export function makePolicyUI(c: Context) {
  let rules: Rule[] = [],
    settings: { site_id: number; settings: Settings }[] = [],
    events: Event[] = [],
    rowID = 0;
  const siteName = (id: number) =>
    c.sites().find((s) => s.id === id)?.name || `Site #${id}`;
  const siteOptions = (selected?: number) =>
    c
      .sites()
      .map(
        (s) =>
          `<option value="${s.id}" ${s.id === selected ? "selected" : ""}>${esc(s.name)} · ${esc(s.hostnames.join(", "))}</option>`,
      )
      .join("");
  async function renderRules() {
    rules = await c.api<Rule[]>("/rules");
    return (
      heading(
        "Rules",
        "Small, application-scoped signatures. Start as a draft, observe, then enforce.",
        btn("import-rule", "Import JSON", "secondary") +
          btn("new-rule", "Create rule", "primary"),
      ) +
      ruleTabs() +
      `<div class="info-panel rule-intro"><h3>You control activation</h3><p>New and edited rules are drafts. Observe records matches; Block returns HTTP 403. Active rules expire automatically. JSON proposals use the same validated format as this editor.</p></div>` +
      (rules.length
        ? table(
            ["Rule", "Proxy host", "Mode", "Expires", ""],
            rules.map((r) => [
              `<strong>${esc(r.spec.name)}</strong><small>${r.spec.all.length} conditions · revision ${r.revision}</small>`,
              `${esc(siteName(r.site_id))}<small class="domain">${esc(r.spec.scope.path_prefix || "All paths (conditions still apply)")}</small>`,
              badge(r.status),
              r.expires_at
                ? esc(new Date(r.expires_at).toLocaleString())
                : "Not activated",
              `<div class="row-actions">${btn("view-rule", "Details", "secondary compact", r.id)}${r.enabled && r.status !== "expired" ? btn("disable-rule", "Disable", "danger compact", r.id) : btn("observe-rule", "Observe", "secondary compact", r.id)}${btn("test-rule", "Test", "subtle compact", r.id)}</div>`,
            ]),
            "Rules",
          )
        : empty(
            "No rules yet",
            "Create a rule or import a JSON proposal. Nothing blocks traffic until you explicitly activate it.",
          )) +
      `<div class="page-note">Rules run in Go against an in-memory snapshot. No model runs on the request path. Missing or incomplete inspection data is reported as unknown.</div>`
    );
  }
  async function renderTraffic() {
    [settings, events] = await Promise.all([
      c.api<typeof settings>("/traffic-settings"),
      c.api<Event[]>("/traffic-events"),
    ]);
    return (
      heading(
        "Traffic evidence",
        "Opt-in, bounded samples for investigating requests and testing rule proposals.",
        btn("refresh", "Refresh", "secondary"),
      ) +
      ruleTabs() +
      `<div class="info-panel rule-intro"><h3>Capture is off by default</h3><p>Choose which fields a site may capture. Credentials, authorization, cookies and sensitive field names cannot be selected. Redaction cannot identify every secret; review your allowlists before enabling capture. Samples remain in your PostgreSQL deployment and its backups; provider connection checks do not submit them.</p></div>` +
      (c.sites().length
        ? table(
            ["Proxy host", "Capture", "Limits", ""],
            c.sites().map((site) => {
              const s =
                settings.find((v) => v.site_id === site.id)?.settings ||
                defaults();
              return [
                `<strong>${esc(site.name)}</strong><small>${site.hostnames.map(esc).join(", ")}</small>`,
                badge(s.enabled ? "enabled" : "disabled"),
                `1 in ${s.sample_every} · up to ${s.max_per_minute}/min per replica<small>${s.retention_hours}h retention · ${s.query_keys.length + s.header_keys.length + s.json_body_keys.length} selected fields</small>`,
                btn(
                  "capture-settings",
                  "Configure",
                  "secondary compact",
                  site.id,
                ),
              ];
            }),
            "Traffic capture settings",
          )
        : empty(
            "Add a proxy host first",
            "Traffic capture is configured separately for each application.",
          )) +
      `<section class="section"><div class="section-heading"><h2>Recent evidence</h2><span class="muted">Latest 100 unexpired samples</span></div>${
        events.length
          ? table(
              ["Time", "Application / path", "Inspection", ""],
              events.map((e) => [
                esc(new Date(e.at).toLocaleString()),
                `${esc(siteName(e.site_id))}<small class="domain">${esc(e.data.facts["method:"]?.values?.[0] || "")} ${esc(e.data.facts["path:"]?.values?.[0] || "Path not captured")}</small>`,
                `${Object.values(e.data.facts).filter((f) => !["present", "missing"].includes(f.state)).length} incomplete/redacted fields<small>${e.data.rule_results?.filter((r) => r.result === "matched").length || 0} rule matches</small>`,
                btn("view-evidence", "Inspect", "secondary compact", e.id),
              ]),
              "Traffic evidence",
            )
          : empty(
              "No captured evidence",
              "Enable capture for a site, then send requests through its proxy host. Samples expire and may be limited by sampling budgets.",
            )
      }</section>`
    );
  }
  function conditionRow(
    value: RuleSpec["all"][number] = { field: "path", op: "equals", value: "" },
  ) {
    const id = ++rowID;
    return `<div class="rule-condition" data-condition="${id}"><div class="condition-top"><label class="field">Field<select name="field">${["method", "path", "client_ip", "header", "query", "json_body"].map((v) => `<option value="${v}" ${v === value.field ? "selected" : ""}>${v}</option>`).join("")}</select></label><label class="field">Operator<select name="op"></select></label>${btn("remove-condition", "Remove", "subtle compact", id)}</div><label class="field key-field">Field key<input name="key" value="${esc(value.key || "")}" maxlength="128" placeholder="q, user-agent, or /file"></label><label class="field">Value<input name="value" required value="${esc(Array.isArray(value.value) ? JSON.stringify(value.value) : value.value)}" maxlength="20000"></label><small class="condition-help"></small></div>`;
  }
  function bindCondition(el: HTMLElement, value?: RuleSpec["all"][number]) {
    const select = el.querySelector<HTMLSelectElement>("[name=field]")!,
      op = el.querySelector<HTMLSelectElement>("[name=op]")!,
      key = el.querySelector<HTMLInputElement>("[name=key]")!,
      input = el.querySelector<HTMLInputElement>("[name=value]")!,
      help = el.querySelector<HTMLElement>(".condition-help")!;
    const updateHelp = () => {
      help.textContent =
        op.value === "in"
          ? 'Enter a JSON array, for example ["GET", "POST"].'
          : op.value === "regex"
            ? "Go/RE2 syntax. Maximum 512 bytes; no lookaround or backreferences."
            : op.value === "cidr"
              ? "Uses the direct connection peer. Forwarded client-IP headers are ignored."
              : "Matching is case sensitive. Query values and paths are decoded once.";
    };
    const update = () => {
      const ops =
        select.value === "method"
          ? ["equals", "in"]
          : select.value === "client_ip"
            ? ["cidr"]
            : ["equals", "in", "contains", "prefix", "regex"];
      const previous = op.value;
      op.innerHTML = ops
        .map((v) => `<option value="${v}">${v}</option>`)
        .join("");
      if (ops.includes(previous)) op.value = previous;
      (el.querySelector(".key-field") as HTMLElement).hidden = ![
        "header",
        "query",
        "json_body",
      ].includes(select.value);
      key.required = !(el.querySelector(".key-field") as HTMLElement).hidden;
      updateHelp();
    };
    select.addEventListener("change", update);
    op.addEventListener("change", updateHelp);
    update();
    if (value) op.value = value.op;
    updateHelp();
    input.spellcheck = false;
  }
  function ruleForm(rule?: Rule) {
    if (!c.sites().length) {
      c.notice("Add a proxy host before creating a rule.", true);
      return;
    }
    c.openEditor(
      rule ? "Edit rule draft" : "Create a rule",
      `<p class="form-intro">All conditions must match. Saving creates a draft and disables any previous active version.</p><form id="rule-form">${field("name", "Rule name", rule?.spec.name || "", "text", 'required maxlength="120" placeholder="Environment file probes"')}<label class="field" for="rule-site">Proxy host</label><select id="rule-site" name="site_id">${siteOptions(rule?.site_id)}</select>${field("path_prefix", "Path prefix (optional)", rule?.spec.scope.path_prefix || "", "text", 'maxlength="1024" placeholder="/api/"')}<div id="conditions">${(rule?.spec.all || [{ field: "path", op: "equals", value: "" }]).map(conditionRow).join("")}</div>${btn("add-condition", "Add condition", "secondary compact")}<label class="field" for="rule-action">Proposed action</label><select id="rule-action" name="action"><option value="observe">Observe</option><option value="block" ${rule?.spec.action === "block" ? "selected" : ""}>Block</option></select>${field("ttl_seconds", "Active lifetime (seconds)", String(rule?.spec.ttl_seconds || 3600), "number", 'required min="60" max="86400"')}<small>Starts on activation. Between 60 seconds and 24 hours.</small>${actions("Save draft")}</form>`,
    );
    document
      .querySelectorAll<HTMLElement>(".rule-condition")
      .forEach((el, i) => bindCondition(el, rule?.spec.all[i]));
    c.formHandler("rule-form", async (f) => {
      const all = Array.from(
        document.querySelectorAll<HTMLElement>(".rule-condition"),
      ).map((el) => {
        const field =
            el.querySelector<HTMLSelectElement>("[name=field]")!.value,
          op = el.querySelector<HTMLSelectElement>("[name=op]")!.value,
          value = el.querySelector<HTMLInputElement>("[name=value]")!.value,
          key = el.querySelector<HTMLInputElement>("[name=key]")!.value;
        return {
          field,
          op,
          value: op === "in" ? JSON.parse(value) : value,
          ...(["header", "query", "json_body"].includes(field) ? { key } : {}),
        };
      });
      const prefix = String(f.get("path_prefix") || "");
      await c.api(
        "/rules" + (rule ? "/" + rule.id : ""),
        rule ? "PUT" : "POST",
        {
          schema_version: 1,
          name: f.get("name"),
          scope: {
            site_id: Number(f.get("site_id")),
            ...(prefix ? { path_prefix: prefix } : {}),
          },
          all,
          action: f.get("action"),
          ttl_seconds: Number(f.get("ttl_seconds")),
        },
      );
      c.closeEditor();
      await c.refresh();
      c.notice("Draft saved. It will not affect traffic until activated.");
    });
  }
  function importForm() {
    const example: RuleSpec = {
      schema_version: 1,
      name: "Environment file probes",
      scope: { site_id: c.sites()[0]?.id || 1 },
      all: [{ field: "path", op: "equals", value: "/.env" }],
      action: "observe",
      ttl_seconds: 3600,
    };
    c.openEditor(
      "Import a rule proposal",
      `<p class="form-intro">Paste JSON from an administrator or a future model integration. The server validates every condition. Imports always start as drafts.</p><form id="import-rule-form"><label class="field" for="rule-json">Rule JSON</label><textarea id="rule-json" name="rule_json" class="json-editor" required spellcheck="false">${esc(JSON.stringify(example, null, 2))}</textarea><a href="/api/rules/schema" target="_blank" rel="noopener noreferrer">Open the JSON schema ↗</a>${actions("Import draft")}</form>`,
    );
    c.formHandler("import-rule-form", async (f) => {
      let spec: unknown;
      try {
        spec = JSON.parse(String(f.get("rule_json")));
      } catch {
        throw new Error(
          "The rule is not valid JSON. Your input has been preserved.",
        );
      }
      await c.api("/rules", "POST", spec);
      c.closeEditor();
      await c.refresh();
      c.notice(
        "Proposal imported as a draft. No traffic policy was activated.",
      );
    });
  }
  async function details(rule: Rule) {
    const history = await c.api<
      {
        id: number;
        actor: string;
        at: string;
        enabled: boolean;
        spec: RuleSpec;
      }[]
    >(`/rules/${rule.id}/history`);
    c.openEditor(
      rule.spec.name,
      `<div class="detail-status">${badge(rule.status)}<span class="muted">Revision ${rule.revision}</span></div><pre class="json-view">${esc(JSON.stringify(rule.spec, null, 2))}</pre><div class="row-actions policy-actions">${btn("edit-rule", "Edit draft", "secondary", rule.id)}${btn("export-rule", "Export JSON", "secondary", rule.id)}${btn("test-rule", "Test against evidence", "secondary", rule.id)}</div><div class="info-panel"><h3>Activate deliberately</h3><p>Observe logs matches and continues proxying. Block returns 403. Both expire after ${rule.spec.ttl_seconds} seconds. Rollback restores the previous state without extending its original expiry.</p></div><div class="row-actions policy-actions">${btn("observe-rule", "Start observing", "primary", rule.id)}${btn("block-rule", "Enforce blocking", "danger", rule.id)}${rule.enabled ? btn("disable-rule", "Disable", "secondary", rule.id) : ""}${history.length ? btn("rollback-rule", "Rollback previous", "secondary", rule.id) : ""}</div>${history.length ? `<details class="advanced"><summary>Recent history</summary>${history.map((h) => `<p>${esc(new Date(h.at).toLocaleString())} · ${esc(h.actor)}<small>Previous state: ${h.enabled ? esc(h.spec.action) : "disabled/draft"}</small></p>`).join("")}</details>` : ""}<div class="form-actions">${btn("delete-rule", "Delete rule", "danger", rule.id)}</div>`,
    );
  }
  function captureForm(id: number) {
    const s = settings.find((v) => v.site_id === id)?.settings || defaults();
    c.openEditor(
      `Traffic capture · ${siteName(id)}`,
      `<p class="form-intro">Capture only what this application needs. Fields not selected here are not persisted in evidence. Treat samples as untrusted data.</p><form id="capture-form">${checkbox("enabled", "Enable bounded traffic sampling", s.enabled)}${checkbox("security_events_disabled", "Disable JSON security events for this application", !!s.security_events_disabled)}${checkbox("security_samples", "Include retained redacted samples in security events", !!s.security_samples)}<small>Security events go to container stdout after the traffic decision. Samples require enabled sampling and field allowlists, and are capped at 2 KiB. Exporting samples can expose personal data; leave off unless required.</small>${checkbox("capture_path", "Capture paths with common token/identifier redaction", s.capture_path)}<small>Paths can still contain personal data. Leave this off when the application uses sensitive URL segments.</small>${field("query_keys", "Query keys (up to four)", s.query_keys.join(", "), "text", 'placeholder="q, file"')}${field("header_keys", "Header keys (up to four)", s.header_keys.join(", "), "text", 'placeholder="user-agent, content-type"')}${field("json_body_keys", "JSON pointers (up to four)", s.json_body_keys.join(", "), "text", 'placeholder="/query, /file"')}<small>Comma-separated allowlists. Passwords, tokens, cookies, authorization and forwarding headers are rejected.</small><label class="field" for="capture-redactions">Additional redaction patterns (one regex per line)</label><textarea id="capture-redactions" name="redact_patterns" rows="3" maxlength="2056">${esc((s.redact_patterns || []).join("\n"))}</textarea><small>Up to eight RE2 patterns, 256 bytes each. A matching evidence value is fully redacted before storage. This does not anonymize access-log IP addresses or existing samples.</small><div class="form-row">${field("sample_every", "Sample one in N requests", String(s.sample_every), "number", 'required min="1" max="10000"')}${field("max_per_minute", "Maximum samples/minute per replica", String(s.max_per_minute), "number", 'required min="1" max="600"')}</div>${field("retention_hours", "Retention for new samples (hours)", String(s.retention_hours), "number", 'required min="1" max="168"')}<small>Existing samples keep their original expiry. Sampling limits are local to each replica.</small>${actions("Save capture settings")}</form>`,
    );
    c.formHandler("capture-form", async (f) => {
      await c.api(`/traffic-settings/${id}`, "PUT", {
        enabled: f.has("enabled"),
        security_events_disabled: f.has("security_events_disabled"),
        security_samples: f.has("security_samples"),
        capture_path: f.has("capture_path"),
        query_keys: csv(f.get("query_keys")),
        header_keys: csv(f.get("header_keys")),
        json_body_keys: csv(f.get("json_body_keys")),
        redact_patterns: String(f.get("redact_patterns") || "")
          .split("\n")
          .map((v) => v.trim())
          .filter(Boolean),
        sample_every: Number(f.get("sample_every")),
        max_per_minute: Number(f.get("max_per_minute")),
        retention_hours: Number(f.get("retention_hours")),
      });
      c.closeEditor();
      await c.refresh();
      c.notice(
        "Capture settings saved. Changes reach replicas within 2 seconds.",
      );
    });
  }
  async function replay(rule: Rule) {
    const samples = await c.api<Event[]>(
      `/traffic-events?site_id=${rule.site_id}`,
    );
    c.openEditor(
      "Test a rule against evidence",
      `<p class="form-intro">This evaluates stored facts locally. It sends no requests to your application. Redacted, truncated and uncaptured fields produce unknown results.</p>${
        samples.length
          ? `<form id="replay-form"><div class="sample-picker">${samples
              .slice(0, 20)
              .map(
                (e) =>
                  `<label class="check"><input type="checkbox" name="event_ids" value="${esc(e.id)}" checked><span>${esc(new Date(e.at).toLocaleString())}<small class="domain">${esc(e.data.facts["method:"]?.values?.[0] || "")} ${esc(e.data.facts["path:"]?.values?.[0] || "Path not captured")}</small></span></label>`,
              )
              .join(
                "",
              )}</div><div id="replay-output" aria-live="polite"></div>${actions("Evaluate locally")}</form>`
          : empty(
              "No evidence for this application",
              "Enable traffic capture, send requests through its proxy host, and try again.",
            )
      }`,
    );
    if (samples.length)
      c.formHandler("replay-form", async (f) => {
        const result = await c.api<{
          counts: { matched: number; not_matched: number; unknown: number };
          live_requests_sent: number;
        }>("/rules/replay", "POST", {
          rule: rule.spec,
          event_ids: f.getAll("event_ids"),
        });
        document.getElementById("replay-output")!.innerHTML =
          `<div class="notice" role="status">${result.counts.matched} matched · ${result.counts.not_matched} not matched · ${result.counts.unknown} unknown. No live requests sent.</div>`;
      });
  }
  async function handleAction(
    action: string | undefined,
    id: number,
    rawID?: string,
  ): Promise<boolean> {
    const rule = rules.find((r) => r.id === id);
    switch (action) {
      case "new-rule":
        ruleForm();
        return true;
      case "import-rule":
        importForm();
        return true;
      case "add-condition": {
        const box = document.getElementById("conditions")!;
        if (box.children.length >= 12)
          throw new Error("A rule can contain at most 12 conditions.");
        box.insertAdjacentHTML("beforeend", conditionRow());
        bindCondition(box.lastElementChild as HTMLElement);
        return true;
      }
      case "remove-condition":
        if (document.querySelectorAll(".rule-condition").length <= 1)
          throw new Error("A rule needs at least one condition.");
        document.querySelector(`[data-condition="${id}"]`)?.remove();
        return true;
      case "capture-settings":
        captureForm(id);
        return true;
      case "view-evidence": {
        const event = events.find((e) => e.id === rawID);
        if (event)
          c.openEditor(
            "Captured evidence",
            `<p class="form-intro">${esc(siteName(event.site_id))} · expires ${esc(new Date(event.expires_at).toLocaleString())}</p><pre class="json-view">${esc(JSON.stringify(event.data, null, 2))}</pre>`,
          );
        return true;
      }
      case "view-rule":
      case "edit-rule":
      case "test-rule":
      case "export-rule":
      case "observe-rule":
      case "block-rule":
      case "disable-rule":
      case "rollback-rule":
      case "delete-rule":
        if (!rule)
          throw new Error(
            "Rule state changed. Refresh the page and try again.",
          );
        break;
      default:
        return false;
    }
    switch (action) {
      case "view-rule":
        await details(rule!);
        break;
      case "edit-rule":
        ruleForm(rule);
        break;
      case "test-rule":
        await replay(rule!);
        break;
      case "export-rule": {
        const blob = new Blob([JSON.stringify(rule!.spec, null, 2) + "\n"], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `aegis-rule-${rule!.id}.json`;
        link.click();
        URL.revokeObjectURL(url);
        break;
      }
      case "observe-rule":
      case "block-rule":
        if (
          action === "block-rule" &&
          !confirm(
            `Activate HTTP 403 blocking for “${rule!.spec.name}” for ${rule!.spec.ttl_seconds} seconds?`,
          )
        )
          return true;
        await c.api(`/rules/${id}/activate`, "POST", {
          action: action === "block-rule" ? "block" : "observe",
          ttl_seconds: rule!.spec.ttl_seconds,
        });
        c.closeEditor();
        await c.refresh();
        c.notice(
          action === "block-rule"
            ? "Blocking activated with a bounded expiry."
            : "Observation activated. Matching traffic will continue to the upstream.",
        );
        break;
      case "disable-rule":
      case "rollback-rule":
        await c.api(
          `/rules/${id}/${action === "disable-rule" ? "disable" : "rollback"}`,
          "POST",
          {},
        );
        c.closeEditor();
        await c.refresh();
        c.notice(
          action === "disable-rule"
            ? "Rule disabled."
            : "Previous rule state restored without extending its expiry.",
        );
        break;
      case "delete-rule":
        if (!confirm("Delete this rule and its revision history?")) return true;
        await c.api(`/rules/${id}`, "DELETE");
        c.closeEditor();
        await c.refresh();
        c.notice("Rule deleted.");
        break;
    }
    return true;
  }
  return { renderRules, renderTraffic, handleAction };
}
