import {
  clearSignatureBrowser,
  mountSignatureBrowser,
} from "./signature-browser";
import {
  defaultManagedSignatures,
  type ManagedSignatures,
  type SignatureSet,
} from "./signature-sets";
export type PolicySummary = {
  id: number;
  name: string;
  mode: string;
  revision: number;
  source_cidrs: string[];
  priority: number;
};
type Rule = { id: number; spec: { name: string; [key: string]: unknown } };
type Group = {
  name: string;
  path_prefix: string;
  methods: string[];
  rules: { rule_id: number; spec: Rule["spec"] }[];
};
type Spec = {
  managed_signatures?: ManagedSignatures;
  name: string;
  description: string;
  mode: string;
  flood_enabled: boolean;
  bot_enabled: boolean;
  block_empty_user_agent: boolean;
  requests_per_second: number;
  burst: number;
  site_requests_per_second: number;
  site_burst: number;
  groups: Group[];
};
type Assignment = { site_id: number; source_cidrs: string[]; priority: number };
type Policy = {
  built_in?: boolean;
  id: number;
  revision: number;
  spec: Spec;
  applications: Assignment[];
};
type Site = { id: number; name: string; policies?: PolicySummary[] };
type C = {
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
  sites: () => Site[];
  esc: (v: unknown) => string;
  heading: (t: string, p: string, b?: string) => string;
  table: (h: string[], r: string[][], label: string) => string;
  openEditor: (t: string, h: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, f: (d: FormData) => Promise<void>) => void;
  refresh: () => Promise<void>;
  notice: (m: string, e?: boolean) => void;
};
export function policySummary(
  policies: PolicySummary[],
  esc: (v: unknown) => string,
) {
  return policies.length
    ? `<div class="info-panel"><strong>Managed by policies</strong><p>${policies.map((p) => `${esc(p.name)} · ${esc(p.mode)} · ${p.source_cidrs.length ? esc(p.source_cidrs.join(", ")) : "Default / all other clients"}`).join("<br>")}</p><a href="#policies">Manage policies and application assignments</a></div>`
    : "";
}
export function makePoliciesPage(c: C) {
  const { api, esc } = c;
  let policies: Policy[] = [];
  const btn = (action: string, label: string, id?: number) =>
    `<button type="button" class="secondary compact" data-action="${action}" ${id ? `data-id="${id}"` : ""}>${label}</button>`;
  async function render() {
    policies = await api<Policy[]>("/policies");
    const assignments = c.sites().map((site) => {
      const bindings = policies
        .flatMap((p) =>
          p.applications
            .filter((a) => a.site_id === site.id)
            .map((a) => ({ p, a })),
        )
        .sort((x, y) => x.a.priority - y.a.priority);
      return [
        `<strong>${esc(site.name)}</strong>`,
        bindings.length
          ? bindings
              .map(
                ({ p, a }) =>
                  `<strong>${esc(p.spec.name)}</strong>${p.built_in ? "<small>Included baseline · editable</small>" : ""}<small>${a.source_cidrs.length ? `${esc(a.source_cidrs.join(", "))} · priority ${a.priority}` : "Default for all other clients"} · ${esc(p.spec.mode)} · v${p.revision}</small>`,
              )
              .join("<br>")
          : '<span class="muted">Local application settings</span>',
      ];
    });
    return (
      c.heading(
        "Policies",
        "Reusable protection, rule groups and source-based application assignments.",
        btn("new-policy", "Create policy"),
      ) +
      `<div class="info-panel"><h3>Match the client, then choose its policy</h3><p>Assign an External default policy first, then add Internal or trusted-office CIDRs at a higher priority. Smaller numbers match first. A CIDR assignment selects a policy; it does not automatically allow all traffic.</p></div>` +
      (policies.length
        ? c.table(
            ["Policy", "Mode", "Groups / rules", "Applications", ""],
            policies.map((p) => [
              `<strong>${esc(p.spec.name)}</strong>${p.built_in ? "<small>Included baseline · editable</small>" : ""}<small>${esc(p.spec.description)}</small><small>Version ${p.revision}</small>`,
              esc(p.spec.mode),
              `${p.spec.groups.length} groups · ${p.spec.groups.reduce((n, g) => n + g.rules.length, 0)} rules${p.spec.managed_signatures && p.spec.managed_signatures.mode !== "off" ? `<small>OWASP CRS · ${esc(p.spec.managed_signatures.mode)}</small>` : ""}`,
              `<span>${p.applications.length} assigned</span>`,
              `<div class="row-actions">${btn("edit-policy", "Edit", p.id)}${btn("assign-policy", "Assign applications", p.id)}${btn("policy-history", "History", p.id)}${btn("delete-policy", "Delete", p.id)}</div>`,
            ]),
            "Protection policies",
          )
        : '<section class="empty-state"><h2>No policies yet</h2><p>Create an External policy and assign it as the default for your applications.</p></section>') +
      `<section class="section"><h2>Application policy routing</h2><p class="muted">CIDR selection uses verified client identity. Unresolved proxy identity uses only the default policy. Headers, proxy trust and component exemptions remain application-specific.</p>${assignments.length ? c.table(["Application", "First-match policy order"], assignments, "Application policy assignments") : "<p>Add a proxy host before assigning a policy.</p>"}</section>`
    );
  }
  async function editor(
    id?: number,
    assignmentFocus = false,
    signaturePreset?: SignatureSet,
  ) {
    const p = policies.find((p) => p.id === id);
    const [rules, sets] = await Promise.all([
      api<Rule[]>("/rules"),
      api<SignatureSet[]>("/signature-sets"),
    ]);
    const spec = p?.spec || {
      name: "",
      description: "",
      mode: "observe",
      flood_enabled: false,
      bot_enabled: false,
      block_empty_user_agent: false,
      requests_per_second: 20,
      burst: 60,
      site_requests_per_second: 1000,
      site_burst: 2000,
      groups: [],
    };
    const savedManaged = spec.managed_signatures || defaultManagedSignatures();
    const managed = signaturePreset
      ? {
          ...(savedManaged.set_id === signaturePreset.id
            ? savedManaged
            : defaultManagedSignatures()),
          set_id: signaturePreset.id,
          mode:
            savedManaged.set_id === signaturePreset.id &&
            savedManaged.mode !== "off"
              ? savedManaged.mode
              : "observe",
        }
      : savedManaged;
    const number = (key: string, label: string, value: number, max: number) =>
      `<label class="field">${label}<input type="number" name="${key}" min="${key === "signature_body_kib" ? 4 : 1}" max="${max}" value="${value}" required></label>`;
    const check = (key: string, label: string, value: boolean) =>
      `<label class="check"><input type="checkbox" name="${key}" ${value ? "checked" : ""}><span>${label}</span></label>`;
    c.openEditor(
      p ? "Edit policy" : "Create policy",
      `<form id="policy-form"><label class="field">Policy name<input name="name" required maxlength="120" value="${esc(spec.name)}" placeholder="External traffic"></label><label class="field">Description<textarea name="description" aria-label="Policy description" maxlength="2000" rows="2">${esc(spec.description)}</textarea></label><label class="field" for="policy-mode">Policy mode</label><select id="policy-mode" name="mode">${["off", "observe", "block"].map((mode) => `<option value="${mode}" ${spec.mode === mode ? "selected" : ""}>${mode === "off" ? "Off" : mode === "observe" ? "Observe · evaluate and allow" : "Block · enforce protection"}</option>`).join("")}</select><h3>Managed signatures</h3><p class="muted">Choose a loaded set to apply its request signatures to this policy. Browse the list to inspect descriptions and choose individual exclusions.</p><label class="field" for="policy-signature-mode">Signature mode</label><select id="policy-signature-mode" name="signature_mode" ${sets.length ? "" : "disabled"}>${["off", "observe", "block"].map((mode) => `<option value="${mode}" ${managed.mode === mode ? "selected" : ""}>${mode === "off" ? "Off" : mode === "observe" ? "Observe · log matches and allow" : "Block · enforce signatures"}</option>`).join("")}</select><label class="field" for="policy-signature-set">Signature set</label><select id="policy-signature-set" name="signature_set"><option value="">Select a loaded set</option>${sets.map((set) => `<option value="${esc(set.id)}" ${managed.set_id === set.id ? "selected" : ""}>${esc(set.name)} ${esc(set.version)}</option>`).join("")}</select>${!sets.length ? '<button type="button" class="secondary compact" data-policy-load-signatures>Load bundled OWASP CRS</button>' : ""}<small>Policy Off disables signatures; policy Observe caps enforcement at Observe. Start with Observe and review false positives before blocking.</small><details class="advanced"><summary>Signature tuning</summary><label class="field" for="signature-paranoia">CRS paranoia level</label><select id="signature-paranoia" name="signature_paranoia">${[1, 2, 3, 4].map((level) => `<option value="${level}" ${managed.paranoia_level === level ? "selected" : ""}>${level}${level === 1 ? " · baseline" : " · stricter"}</option>`).join("")}</select>${number("signature_threshold", "CRS inbound anomaly threshold", managed.inbound_threshold, 100)}${number("signature_body_kib", "Inspected body limit (KiB)", managed.body_limit_bytes / 1024, 1024)}<small>Block rejects bodies above this limit with 413. Observe forwards the full body and marks capped inspection. Responses continue streaming.</small><label class="field">Excluded CRS rule IDs<input name="signature_exclusions" value="${esc(managed.excluded_rule_ids.join(", "))}" placeholder="942100, 941100"></label><small>Use IDs from observed matches for targeted policy exclusions. This does not disable your custom signature groups.</small></details><button type="button" class="secondary compact" data-policy-browse-signatures>Browse signatures and exclusions</button><div data-policy-signature-browser hidden></div><h3>Shared protection</h3>${check("flood_enabled", "Enable HTTP flood protection", spec.flood_enabled)}<div class="form-grid">${number("requests_per_second", "Requests / second per client", spec.requests_per_second, 100000)}${number("burst", "Client burst allowance", spec.burst, 1000000)}${number("site_requests_per_second", "Requests / second per application", spec.site_requests_per_second, 1000000)}${number("site_burst", "Application burst allowance", spec.site_burst, 2000000)}</div><small>Budgets are per application, selected policy and replica. Internal-policy traffic does not consume External-policy budgets.</small>${check("bot_enabled", "Enable anti-bot signals", spec.bot_enabled)}${check("block_empty_user_agent", "Flag missing User-Agent", spec.block_empty_user_agent)}<h3>Rule groups</h3><div id="policy-groups"></div><button type="button" class="secondary compact" data-add-policy-group>Add rule group</button>${p ? check("refresh_rules", "Refresh selected rule snapshots from the library", false) : ""}<small>Groups contain frozen copies of selected signatures. Library edits and feed syncs do not change a published policy until you explicitly refresh and save.</small><section id="policy-assignment-section"><h3>Application assignments</h3><p class="muted">Select All other clients for the default policy. An application needs a default before adding CIDR policies. Choosing a new default replaces its previous default assignment. Assigned policies replace local bot/flood and local-rule activation; client identity, headers and CIDR exceptions stay local.</p><div id="policy-assignments"></div><button type="button" class="secondary compact" data-add-policy-assignment>Add application</button></section><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Save policy">Save policy</button></div></form>`,
    );
    const form = document.getElementById("policy-form") as HTMLFormElement;
    const modeSelect = form.elements.namedItem(
      "signature_mode",
    ) as HTMLSelectElement;
    const setSelect = form.elements.namedItem(
      "signature_set",
    ) as HTMLSelectElement;
    const updateRequired = () => {
      setSelect.required = modeSelect.value !== "off";
    };
    modeSelect.addEventListener("change", updateRequired);
    updateRequired();
    form
      .querySelector<HTMLButtonElement>("[data-policy-load-signatures]")
      ?.addEventListener("click", async (e) => {
        const button = e.currentTarget as HTMLButtonElement;
        button.disabled = true;
        try {
          const available = await api<{ set: SignatureSet }[]>(
            "/signature-sets/catalogue",
          );
          if (!available.length)
            throw new Error("No bundled signature sets available");
          const loaded = await api<SignatureSet>("/signature-sets", "POST", {
            id: available[0].set.id,
          });
          sets.push(loaded);
          setSelect.add(
            new Option(loaded.name + " " + loaded.version, loaded.id),
          );
          setSelect.value = loaded.id;
          modeSelect.disabled = false;
          modeSelect.value = "observe";
          updateRequired();
          button.textContent = "Signature set loaded";
          updateBrowse();
        } catch (error) {
          button.disabled = false;
          c.notice(
            error instanceof Error
              ? error.message
              : "Could not load signature set",
            true,
          );
        }
      });
    const browser = form.querySelector<HTMLElement>(
      "[data-policy-signature-browser]",
    )!;
    const browseButton = form.querySelector<HTMLButtonElement>(
      "[data-policy-browse-signatures]",
    )!;
    let browserSet = "";
    const updateBrowse = () => {
      browseButton.disabled = !setSelect.value;
    };
    updateBrowse();
    setSelect.addEventListener("change", () => {
      browser.hidden = true;
      clearSignatureBrowser(browser);
      browserSet = "";
      updateBrowse();
    });
    browseButton.addEventListener("click", async () => {
      if (!setSelect.value) return;
      browseButton.disabled = true;
      try {
        browser.hidden = false;
        if (browserSet !== setSelect.value) {
          const selectedSet = setSelect.value;
          await mountSignatureBrowser(browser, selectedSet, {
            api,
            esc,
            exclusions: form.elements.namedItem(
              "signature_exclusions",
            ) as HTMLInputElement,
          });
          if (selectedSet === setSelect.value) browserSet = selectedSet;
        }
        browser.scrollIntoView({ block: "nearest" });
      } catch (error) {
        c.notice(
          error instanceof Error ? error.message : "Could not load signatures",
          true,
        );
      } finally {
        updateBrowse();
      }
    });
    const addGroup = (g?: Group) => {
      const all = [...rules];
      for (const old of g?.rules || [])
        if (!all.some((r) => r.id === old.rule_id))
          all.push({ id: old.rule_id, spec: old.spec });
      const selected = new Set((g?.rules || []).map((r) => r.rule_id));
      form
        .querySelector("#policy-groups")!
        .insertAdjacentHTML(
          "beforeend",
          `<fieldset class="policy-group" data-policy-group><legend>Rule group</legend><label class="field">Group name<input data-group-name required maxlength="120" value="${esc(g?.name || "Baseline")}"></label><label class="field">Path prefix<input data-group-path maxlength="1024" value="${esc(g?.path_prefix || "")}" placeholder="/api/ (empty means all paths)"></label><label class="field">Methods<input data-group-methods value="${esc((g?.methods || []).join(", "))}" placeholder="GET, POST (empty means all methods)"></label><div class="policy-rule-picker" role="group" aria-label="Group signatures">${all.length ? all.map((rule) => `<label class="check"><input type="checkbox" data-group-rule value="${rule.id}" ${selected.has(rule.id) ? "checked" : ""}><span>${esc(rule.spec.name)} <small>#${rule.id}</small></span></label>`).join("") : '<p class="muted">Create or import signatures in Rules first.</p>'}</div><button type="button" class="subtle compact" data-remove-policy-group>Remove group</button></fieldset>`,
        );
    };
    const addAssignment = (a?: Assignment) => {
      const sites = c.sites();
      if (!sites.length) {
        c.notice("Create an application before assigning a policy.", true);
        return;
      }
      const assigned = new Set(
        Array.from(
          form.querySelectorAll<HTMLSelectElement>("[data-assignment-site]"),
        ).map((el) => Number(el.value)),
      );
      const first = sites.find((s) => !assigned.has(s.id)) || sites[0];
      form
        .querySelector("#policy-assignments")!
        .insertAdjacentHTML(
          "beforeend",
          `<fieldset class="policy-assignment" data-policy-assignment><legend>Application assignment</legend><label class="field">Application<select data-assignment-site aria-label="Assignment application">${sites.map((site) => `<option value="${site.id}" ${site.id === (a?.site_id || first.id) ? "selected" : ""}>${esc(site.name)}</option>`).join("")}</select></label><label class="field">Client scope<select data-assignment-scope aria-label="Client scope"><option value="default" ${!a?.source_cidrs.length ? "selected" : ""}>All other clients · default</option><option value="cidr" ${a?.source_cidrs.length ? "selected" : ""}>Specific IPs / CIDRs</option></select></label><div data-assignment-specific ${a?.source_cidrs.length ? "" : "hidden"}><label class="field">Client IPs / CIDRs<textarea data-assignment-cidrs aria-label="Policy client IPs / CIDRs" rows="2" placeholder="192.168.0.0/16">${esc((a?.source_cidrs || []).join("\n"))}</textarea></label><label class="field">Priority<input data-assignment-priority type="number" min="0" max="9999" value="${a && a.priority < 10000 ? a.priority : 100}"></label><small>Lowest matching priority wins. Defaults always run last.</small></div><button type="button" class="subtle compact" data-remove-policy-assignment>Remove assignment</button></fieldset>`,
        );
    };
    for (const group of spec.groups) addGroup(group);
    for (const a of p?.applications || []) addAssignment(a);
    form.addEventListener("click", (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>(
        "[data-add-policy-group],[data-remove-policy-group],[data-add-policy-assignment],[data-remove-policy-assignment]",
      );
      if (!target) return;
      if (target.hasAttribute("data-add-policy-group")) {
        if (form.querySelectorAll("[data-policy-group]").length < 10)
          addGroup();
      } else if (target.hasAttribute("data-remove-policy-group"))
        target.closest("[data-policy-group]")!.remove();
      else if (target.hasAttribute("data-add-policy-assignment"))
        addAssignment();
      else target.closest("[data-policy-assignment]")!.remove();
    });
    form.addEventListener("change", (e) => {
      const el = e.target as HTMLSelectElement;
      if (el.hasAttribute("data-assignment-scope"))
        el
          .closest("[data-policy-assignment]")!
          .querySelector<HTMLElement>("[data-assignment-specific]")!.hidden =
          el.value !== "cidr";
    });
    if (assignmentFocus)
      form
        .querySelector("#policy-assignment-section")!
        .scrollIntoView({ block: "start" });
    c.formHandler("policy-form", async (f) => {
      const value = (name: string) => Number(f.get(name));
      const groups = Array.from(
        form.querySelectorAll<HTMLElement>("[data-policy-group]"),
      ).map((g) => ({
        name: g.querySelector<HTMLInputElement>("[data-group-name]")!.value,
        path_prefix:
          g.querySelector<HTMLInputElement>("[data-group-path]")!.value,
        methods: g
          .querySelector<HTMLInputElement>("[data-group-methods]")!
          .value.split(/[\s,]+/)
          .filter(Boolean),
        rule_ids: Array.from(
          g.querySelectorAll<HTMLInputElement>("[data-group-rule]:checked"),
        ).map((el) => Number(el.value)),
      }));
      const applications = Array.from(
        form.querySelectorAll<HTMLElement>("[data-policy-assignment]"),
      ).map((a) => {
        const specific =
          a.querySelector<HTMLSelectElement>("[data-assignment-scope]")!
            .value === "cidr";
        const cidrs = a
          .querySelector<HTMLTextAreaElement>("[data-assignment-cidrs]")!
          .value.split(/[\s,]+/)
          .filter(Boolean);
        if (specific && !cidrs.length)
          throw new Error(
            "Enter at least one IP or CIDR for a scoped assignment.",
          );
        return {
          site_id: Number(
            a.querySelector<HTMLSelectElement>("[data-assignment-site]")!.value,
          ),
          source_cidrs: specific ? cidrs : [],
          priority: specific
            ? Number(
                a.querySelector<HTMLInputElement>("[data-assignment-priority]")!
                  .value,
              )
            : 10000,
        };
      });
      await api(`/policies${p ? `/${p.id}` : ""}`, p ? "PUT" : "POST", {
        revision: p?.revision || 0,
        refresh_rules: f.has("refresh_rules"),
        spec: {
          name: f.get("name"),
          description: f.get("description"),
          mode: f.get("mode"),
          flood_enabled: f.has("flood_enabled"),
          bot_enabled: f.has("bot_enabled"),
          block_empty_user_agent: f.has("block_empty_user_agent"),
          requests_per_second: value("requests_per_second"),
          burst: value("burst"),
          site_requests_per_second: value("site_requests_per_second"),
          site_burst: value("site_burst"),
          managed_signatures: {
            set_id: String(f.get("signature_set") || ""),
            mode: String(f.get("signature_mode") || "off"),
            paranoia_level: Number(f.get("signature_paranoia")),
            inbound_threshold: Number(f.get("signature_threshold")),
            body_limit_bytes: Number(f.get("signature_body_kib")) * 1024,
            excluded_rule_ids: String(f.get("signature_exclusions") || "")
              .split(/[\s,]+/)
              .filter(Boolean)
              .map(Number),
          },
          groups,
        },
        applications,
      });
      c.closeEditor();
      await c.refresh();
      c.notice("Policy saved. Assigned applications update automatically.");
    });
  }
  async function history(id: number) {
    const p = policies.find((p) => p.id === id);
    if (!p) return;
    const versions = await api<
      { revision: number; spec: Spec; at: string; actor: string }[]
    >(`/policies/${id}/history`);
    c.openEditor(
      `${p.spec.name} · history`,
      c.table(
        ["Version", "Mode", "Saved", ""],
        versions.map((v) => [
          String(v.revision),
          esc(v.spec.mode),
          esc(new Date(v.at).toLocaleString()),
          v.revision === p.revision
            ? "Current"
            : `<button class="secondary compact" data-action="rollback-policy" data-id="${id}" data-version="${v.revision}">Restore</button>`,
        ]),
        "Policy versions",
      ) +
        `<p class="muted">Restore changes the policy's protection and rule snapshots for its current assignments. It does not restore old assignments.</p>`,
    );
  }
  async function handle(
    action: string | undefined,
    id: number,
    button: HTMLElement,
  ) {
    const p = policies.find((p) => p.id === id);
    switch (action) {
      case "new-policy":
        await editor();
        return true;
      case "edit-policy":
        await editor(id);
        return true;
      case "assign-policy":
        await editor(id, true);
        return true;
      case "policy-history":
        await history(id);
        return true;
      case "rollback-policy":
        if (
          p &&
          confirm("Restore this policy version for its current applications?")
        ) {
          await api(`/policies/${id}/rollback`, "POST", {
            revision: p.revision,
            target_revision: Number(button.dataset.version),
          });
          c.closeEditor();
          await c.refresh();
          c.notice(
            "Policy version restored. Current application assignments were retained.",
          );
        }
        return true;
      case "delete-policy":
        if (
          p &&
          confirm(
            "Delete this policy and its assignments? Applications without policies return to local protection settings.",
          )
        ) {
          await api(`/policies/${id}`, "DELETE", { revision: p.revision });
          await c.refresh();
          c.notice("Policy removed.");
        }
        return true;
      default:
        return false;
    }
  }
  async function applySignatureSet(set: SignatureSet) {
    policies = await api<Policy[]>("/policies");
    if (!policies.length) {
      await editor(undefined, false, set);
      return;
    }
    c.openEditor(
      "Apply signature set to a policy",
      `<p>Choose where to configure ${esc(set.name)} ${esc(set.version)}. The next form preserves existing application assignments and rule groups. Nothing changes until you save it.</p><form id="signature-policy-form"><label class="field">Policy<select name="policy" aria-label="Policy"><option value="">Create a new policy</option>${policies.map((policy) => `<option value="${policy.id}">${esc(policy.spec.name)}</option>`).join("")}</select></label><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Configure policy">Configure policy</button></div></form>`,
    );
    c.formHandler("signature-policy-form", async (data) => {
      await editor(Number(data.get("policy")) || undefined, false, set);
    });
  }
  return { render, handle, applySignatureSet };
}
