import { openSignatureBuilder } from "./signature-set-builder";
import { mountSignatureBrowser } from "./signature-browser";
import { ruleTabs } from "./rule-tabs";
export type SignatureSet = {
  curation?: {
    source_set_id: string;
    source_version: string;
    source_digest: string;
    selected_rule_ids: number[];
  };
  id: string;
  name: string;
  version: string;
  digest: string;
  rule_count: number;
};
export type ManagedSignatures = {
  set_id: string;
  mode: string;
  paranoia_level: number;
  inbound_threshold: number;
  body_limit_bytes: number;
  body_limit_action: string;
  response_mode: string;
  response_body_limit_bytes: number;
  response_body_limit_action: string;
  outbound_threshold: number;
  excluded_rule_ids: number[];
  scoped_exclusions?: {
    rule_ids: number[];
    path_prefix?: string;
    client_cidrs?: string[];
    parameters?: string[];
  }[];
};
export const defaultManagedSignatures = (): ManagedSignatures => ({
  set_id: "",
  mode: "off",
  paranoia_level: 1,
  inbound_threshold: 5,
  body_limit_bytes: 65536,
  body_limit_action: "reject",
  response_mode: "off",
  response_body_limit_bytes: 262144,
  response_body_limit_action: "reject",
  outbound_threshold: 4,
  excluded_rule_ids: [],
});
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  esc: (value: unknown) => string;
  heading: (title: string, text: string, buttons?: string) => string;
  table: (headers: string[], rows: string[][], label: string) => string;
  refresh: () => Promise<void>;
  notice: (message: string, error?: boolean) => void;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
  applyToPolicy: (set: SignatureSet) => Promise<void>;
};
export function makeSignatureSetsUI(c: Context) {
  let knownSets: SignatureSet[] = [];
  let loadedSets: SignatureSet[] = [];
  let catalogue: {
    set: SignatureSet;
    loaded: boolean;
    engine_version: string;
  }[] = [];
  async function render() {
    const [available, loaded] = await Promise.all([
      c.api<typeof catalogue>("/signature-sets/catalogue"),
      c.api<SignatureSet[]>("/signature-sets"),
    ]);
    catalogue = available;
    loadedSets = loaded;
    knownSets = [...loaded, ...available.map((item) => item.set)];
    return (
      c.heading(
        "Rules",
        "Load a source or craft a reusable detection set, then choose its sensitivity in a policy.",
        `<button type="button" class="secondary" data-action="create-curated-set">Create curated set</button>`,
      ) +
      ruleTabs("sets") +
      `<div class="info-panel"><h3>Start in Observe</h3><p>OWASP CRS provides request signatures and optional response inspection through Coraza. Loading a set does not enable it. Policies choose its mode, body limit and targeted rule exclusions. Loaded versions stay unchanged until you explicitly select another version.</p></div>` +
      c.table(
        ["Available set", "Version / engine", "Bundle entries", ""],
        available.map((item) => [
          `<strong>${c.esc(item.set.name)}</strong><small>Request headers and bounded request bodies</small>`,
          `${c.esc(item.set.version)}<small>Coraza ${c.esc(item.engine_version)}</small>`,
          String(item.set.rule_count),
          `<div class="row-actions"><button type="button" class="secondary compact" data-action="view-signature-set" data-id="${c.esc(item.set.id)}">View signatures</button><button type="button" class="secondary compact" data-action="apply-signature-set" data-id="${c.esc(item.set.id)}">${item.loaded ? "Apply to policy" : "Load & apply to policy"}</button>${item.loaded ? '<span class="badge success">Loaded</span>' : `<button class="primary compact" data-action="load-signature-set" data-id="${c.esc(item.set.id)}">Load signature set</button>`}</div>`,
        ]),
        "Available signature sets",
      ) +
      `<section class="section"><div class="section-heading"><h2>Loaded signature sets</h2><a href="#policies">Manage policy assignments</a></div>${
        loaded.length
          ? c.table(
              ["Set", "Version", "Checksum", ""],
              loaded.map((set) => [
                `<strong>${c.esc(set.name)}</strong>${set.curation ? `${available.some((item) => item.set.id !== set.curation!.source_set_id) ? '<small class="badge warning">Bundled source differs · review upstream</small>' : ""}<small>${set.curation.selected_rule_ids.length} selected detection rules · support retained</small><details><summary>Source provenance</summary><small>${c.esc(set.curation.source_set_id)} · ${c.esc(set.curation.source_version)}</small><code>${c.esc(set.curation.source_digest)}</code></details>` : ""}`,
                c.esc(set.version),
                `<code>${c.esc(set.digest.slice(0, 12))}</code>`,
                `<div class="row-actions"><button type="button" class="secondary compact" data-action="view-signature-set" data-id="${c.esc(set.id)}">View signatures</button><button type="button" class="secondary compact" data-action="apply-signature-set" data-id="${c.esc(set.id)}">Apply to policy</button>${set.curation ? `<button type="button" class="secondary compact" data-action="review-curated-set" data-id="${c.esc(set.id)}">Review upstream</button>` : ""}</div>`,
              ]),
              "Loaded signature sets",
            )
          : '<p class="muted">No managed signature sets loaded yet.</p>'
      }</section>`
    );
  }
  async function handle(action: string | undefined, id: string) {
    if (action === "create-curated-set") {
      await openSignatureBuilder(c, loadedSets);
      return true;
    }
    if (action === "review-curated-set") {
      const frozen = loadedSets.find((s) => s.id === id);
      if (!frozen?.curation) throw new Error("Choose a curated set.");
      const update = await c.api<{
        available: boolean;
        source: SignatureSet;
        changed_rule_ids: number[];
        removed_rule_ids: number[];
      }>(`/signature-sets/${encodeURIComponent(id)}/updates`);
      if (!update.available) {
        c.notice(
          "This curated set is pinned to the current bundled source. No newer source is available.",
        );
        return true;
      }
      if (!loadedSets.some((s) => s.id === update.source.id))
        loadedSets.push(
          await c.api<SignatureSet>("/signature-sets", "POST", {
            id: update.source.id,
          }),
        );
      await openSignatureBuilder(c, loadedSets, {
        source: update.source.id,
        name: frozen.name,
        selected: frozen.curation.selected_rule_ids.filter(
          (id) => !update.removed_rule_ids.includes(id),
        ),
        note: `Source changed: ${update.changed_rule_ids.length} selected rules are in changed files or depend on changed shared data; ${update.removed_rule_ids.length} were removed. Review all source changes before saving a new immutable set. Published policies remain pinned.`,
      });
      return true;
    }
    if (
      ![
        "load-signature-set",
        "view-signature-set",
        "apply-signature-set",
      ].includes(action || "")
    )
      return false;
    let set = knownSets.find((item) => item.id === id);
    if (!set)
      throw new Error("Reload the signature catalogue before selecting a set.");
    if (action === "view-signature-set") {
      c.openEditor(
        `${set.name} ${set.version} · signatures`,
        `<div id="signature-browser"></div><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Close</button><button type="button" class="primary" data-action="apply-signature-set" data-id="${c.esc(id)}">Apply to policy</button></div>`,
      );
      await mountSignatureBrowser(
        document.getElementById("signature-browser")!,
        id,
        c,
      );
      return true;
    }
    if (
      !catalogue.some((item) => item.set.id === id && item.loaded) &&
      catalogue.some((item) => item.set.id === id)
    )
      set = await c.api<SignatureSet>("/signature-sets", "POST", { id });
    if (action === "apply-signature-set") {
      await c.applyToPolicy(set);
      return true;
    }
    await c.refresh();
    c.notice(
      "Signature set loaded. Choose View signatures to inspect rules or Apply to policy to configure protection.",
    );
    return true;
  }
  return { render, handle };
}

export type ManagedSignatureResult = {
  set_id?: string;
  version?: string;
  mode?: string;
  rule_ids?: number[];
  matched_count?: number;
  inspection?: string;
  response_inspection?: string;
  response_mode?: string;
};
const inspectionLabel = (value: string): string =>
  ({
    complete: "Complete",
    partial: "Prefix inspected; remaining bytes uninspected",
    skipped_content_type: "Body skipped for this content type",
    skipped_stream: "Event stream; body not inspected",
    skipped_upgrade: "Protocol upgrade; body not inspected",
    no_body: "No body",
    not_reached: "Response phase not reached",
    unsupported_encoding: "Unsupported content encoding",
    body_limit: "Body exceeds limit",
    match: "Blocked by response signatures",
    read_error_or_timeout: "Upstream read failed or timed out",
    error: "Inspection failed",
    headers: "Blocked by response header rules",
  })[value] || value.replaceAll("_", " ");
export function managedSignatureSummary(
  result: ManagedSignatureResult | undefined,
  esc: (v: unknown) => string,
) {
  if (!result?.set_id) return "";
  const ids = (result.rule_ids || [])
    .slice(0, 8)
    .map((id) => `#${id}`)
    .join(", ");
  return `<small>OWASP CRS ${esc(result.version)} · ${esc(result.mode)}</small>${ids ? `<small>${esc(ids)}${(result.matched_count || 0) > 8 ? " …" : ""}</small>` : ""}${result.inspection && result.inspection !== "complete" ? `<small>Request inspection: ${esc(result.inspection)}</small>` : ""}${result.response_inspection ? `<small>Response ${esc(result.response_mode || "inspection")}: ${esc(inspectionLabel(result.response_inspection))}</small>` : ""}`;
}
