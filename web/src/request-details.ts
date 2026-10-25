import { responseSource } from "./response-status";
import type { Access } from "./types";
import { managedSignatureSummary } from "./signature-sets";
import type { SignatureEntry } from "./signature-browser";
type Detail = {
  event: Access & {
    country: string;
    blocked: boolean;
    signals: string[];
    policy_id: number;
  };
  application: { name: string | null; current_hostnames: string[] | null };
  policy_snapshot: unknown;
  custom_rules: {
    rule_id: number;
    name: string;
    action: string;
    result: string;
    group?: string;
    definition_source: string;
    definition?: unknown;
  }[];
  managed_rules: SignatureEntry[];
  managed_metadata: string;
  evidence_state: string;
  evidence_expires_at: string | null;
  evidence: {
    facts: Record<string, { state: string; values?: string[] }>;
    content_type?: string;
    body_length: number;
  } | null;
};
type Context = {
  api: <T>(p: string) => Promise<T>;
  esc: (v: unknown) => string;
  table: (headers: string[], rows: string[][], label: string) => string;
  openEditor: (title: string, html: string) => void;
};
export function makeRequestDetails(c: Context) {
  return async (id: number) => {
    const detail = await c.api<Detail>(`/access-logs/${id}`);
    const { event } = detail;
    const { esc } = c;
    const flagged =
      event.signals.length > 0 ||
      event.rule_results.some(
        (rule) => rule.result === "matched" && rule.action === "observe",
      );
    const decision = event.blocked
      ? "Blocked"
      : flagged
        ? "Flagged · allowed"
        : "Allowed";
    const row = (key: string, value: unknown) =>
      `<div><dt>${esc(key)}</dt><dd>${esc(value ?? "Unavailable")}</dd></div>`;
    const unavailable =
      detail.evidence_state === "not_captured"
        ? "No request-content sample was retained. Capture may be disabled or this request may not have been sampled."
        : "The retained request-content sample has expired or was removed.";
    const definitions = detail.custom_rules.map((rule) => [
      `#${rule.rule_id} · ${esc(rule.name || "Definition unavailable")}`,
      `${esc(rule.action)} · ${esc(rule.result)}${rule.group ? `<small>Group: ${esc(rule.group)}</small>` : ""}`,
      `${rule.definition_source === "policy_snapshot" ? "Recorded policy snapshot" : rule.definition_source === "current_library" ? "Current library definition · may differ from the original" : "Historical definition unavailable"}${rule.definition ? `<details><summary>Rule definition</summary><pre>${esc(JSON.stringify(rule.definition, null, 2))}</pre></details>` : ""}`,
    ]);
    const facts = Object.entries(detail.evidence?.facts || {}).map(
      ([key, fact]) => [
        esc(key),
        esc(fact.state),
        (fact.values || []).map((value) => esc(value)).join("<br>") || "—",
      ],
    );
    const controlMatches = detail.managed_rules.filter(
      (rule) => rule.has_message === false,
    );
    const managed = detail.managed_rules
      .filter((rule) => rule.has_message !== false)
      .map((rule) => [
        `#${rule.id} · ${esc(rule.name)}`,
        `${esc(rule.category)}<small>${esc(rule.severity)} · phase ${rule.phase}${rule.paranoia_level ? ` · paranoia ${rule.paranoia_level}` : ""}</small>`,
        esc(rule.tags.join(", ")),
      ]);
    c.openEditor(
      `Request #${id}`,
      `<section class="request-detail"><div class="info-panel"><h3>${esc(decision)}</h3><p>${esc(event.method)} · HTTP ${event.status} · ${esc(detail.application.name || `Application ${event.site_id}`)}</p></div><dl class="request-summary">${row("Time", new Date(event.at).toLocaleString())}${row("Client IP", event.peer)}${event.client_objects?.length ? row("Current IP objects", event.client_objects.join(", ")) : ""}${row("Response source", responseSource(event.response_source || (event.blocked ? "waf" : "unknown")))}${row("Duration", `${event.duration_ms} ms`)}${row("Country", event.country || "Unknown")}${row("Region / state", event.region_name || event.region_code || "Unknown")}${row("Policy", event.policy_name ? `${event.policy_name} · v${event.policy_revision}` : "Local application settings")}${row("Current application domains", detail.application.current_hostnames?.join(", ") || "Application removed")}</dl>${event.network_access?.decision ? `<h3>Network access decision</h3><p>${esc(event.network_access.decision)} · ${esc(event.network_access.mode)}${event.network_access.cidr ? ` · ${esc(event.network_access.cidr)}` : ""}</p><p>${event.network_access.allow_scope ? `CIDR allow scope: ${esc(event.network_access.allow_scope === "all" ? "All WAF protections" : "Geo only")}` : event.network_access.geo_checked ? `Geo country: ${esc(event.network_access.country || "Unknown")}` : "Geo lookup skipped after CIDR decision"}</p>` : ""}<h3>Decision and signals</h3><p>${event.signals.length ? event.signals.map((signal) => esc(signal)).join(", ") : "No bot/flood or managed-signature signals recorded."}</p><p>Component exemptions: ${event.protection_exemptions?.length ? event.protection_exemptions.map(esc).join(", ") : "None"}</p><h3>Custom rule results</h3>${definitions.length ? c.table(["Rule", "Recorded result", "Definition"], definitions, "Request custom rule results") : "<p>No custom rule results recorded.</p>"}<h3>Managed signature matches</h3>${managedSignatureSummary(event.managed_signatures, esc)}${controlMatches.length ? `<p>${controlMatches.length} engine control matches in this older record are not attack detections.</p><details><summary>Engine control entries</summary><p>${controlMatches.map((rule) => `#${rule.id}`).join(", ")}</p></details>` : ""}${managed.length ? c.table(["Signature", "Classification", "Tags"], managed, "Request managed signature matches") : detail.managed_metadata === "unavailable" ? "<p>Stored signature metadata is unavailable. Recorded IDs above are retained.</p>" : "<p>No managed-signature matches recorded. An earlier decision may have skipped signature inspection.</p>"}<h3>Retained request evidence</h3>${detail.evidence ? `<p>${esc(detail.evidence.content_type || "Content type unavailable")} · declared body length ${detail.evidence.body_length} · expires ${esc(new Date(detail.evidence_expires_at!).toLocaleString())}</p>${c.table(["Field", "Capture state", "Retained values"], facts, "Request retained facts")}` : `<p>${esc(unavailable)}</p><p>Headers, query fields and body facts require opt-in capture under Traffic. Uncaptured data cannot be reconstructed.</p>`}${detail.policy_snapshot ? `<details><summary>Recorded policy definition</summary><pre>${esc(JSON.stringify(detail.policy_snapshot, null, 2))}</pre></details>` : ""}<details><summary>Recorded event JSON</summary><pre>${esc(JSON.stringify(event, null, 2))}</pre></details><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Close</button></div></section>`,
    );
  };
}
