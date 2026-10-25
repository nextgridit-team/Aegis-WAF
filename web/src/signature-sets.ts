import { mountSignatureBrowser } from "./signature-browser";
import { ruleTabs } from "./rule-tabs";
export type SignatureSet = {
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
  applyToPolicy: (set: SignatureSet) => Promise<void>;
};
export function makeSignatureSetsUI(c: Context) {
  let knownSets: SignatureSet[] = [];
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
    knownSets = [...loaded, ...available.map((item) => item.set)];
    return (
      c.heading(
        "Rules",
        "Load a versioned signature set, then select it in a protection policy.",
      ) +
      ruleTabs("sets") +
      `<div class="info-panel"><h3>Start in Observe</h3><p>OWASP CRS adds established request signatures through Coraza. Loading a set does not enable it. Policies choose its mode, body limit and targeted rule exclusions. Loaded versions stay unchanged until you explicitly select another version.</p></div>` +
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
                `<strong>${c.esc(set.name)}</strong>`,
                c.esc(set.version),
                `<code>${c.esc(set.digest.slice(0, 12))}</code>`,
                `<div class="row-actions"><button type="button" class="secondary compact" data-action="view-signature-set" data-id="${c.esc(set.id)}">View signatures</button><button type="button" class="secondary compact" data-action="apply-signature-set" data-id="${c.esc(set.id)}">Apply to policy</button></div>`,
              ]),
              "Loaded signature sets",
            )
          : '<p class="muted">No managed signature sets loaded yet.</p>'
      }</section>`
    );
  }
  async function handle(action: string | undefined, id: string) {
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
};
export function managedSignatureSummary(
  result: ManagedSignatureResult | undefined,
  esc: (v: unknown) => string,
) {
  if (!result?.set_id) return "";
  const ids = (result.rule_ids || [])
    .slice(0, 8)
    .map((id) => `#${id}`)
    .join(", ");
  return `<small>OWASP CRS ${esc(result.version)} · ${esc(result.mode)}</small>${ids ? `<small>${esc(ids)}${(result.matched_count || 0) > 8 ? " …" : ""}</small>` : ""}${result.inspection && result.inspection !== "complete" ? `<small>Inspection: ${esc(result.inspection)}</small>` : ""}`;
}
