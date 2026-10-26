export type CommunityRule = {
  id: number;
  revision?: number;
  pack?: string;
  cves?: string[];
  spec: { name: string; [key: string]: unknown };
  metadata?: {
    affected_versions: string;
    technology: string[];
    coverage: string;
    limitations: string;
    false_positive_risk: string;
    references: string[];
  };
};
export type CommunitySelection = {
  enabled: boolean;
  rules: {
    rule_id: number;
    spec: CommunityRule["spec"];
    feed?: { revision: number; digest: string; pack: string };
  }[];
};
export function communityMarkup(
  available: CommunityRule[],
  saved: CommunitySelection,
  esc: (v: unknown) => string,
) {
  const items = [...available];
  for (const old of saved.rules)
    if (!items.some((r) => r.id === old.rule_id))
      items.push({ id: old.rule_id, spec: old.spec, pack: old.feed?.pack });
  const selected = new Set(saved.rules.map((r) => r.rule_id));
  return `<section data-community><h3>Community mitigations</h3><label class="check"><input type="checkbox" name="community_enabled" ${saved.enabled ? "checked" : ""}><span>Enable community mitigations</span></label><p class="muted">Choose all available rules or individual mitigations for this policy. These header guards can block legitimate uploads; review compatibility before enforcing. Published copies stay pinned until explicitly refreshed.</p><div data-community-options ${saved.enabled ? "" : "hidden"}><label class="check"><input type="checkbox" data-community-all><span>All available mitigations</span></label><label class="field">Find community mitigations<input type="search" data-community-search placeholder="Name, CVE or technology"></label><div class="policy-rule-picker" role="group" aria-label="Community mitigation rules">${
    items
      .map((rule) => {
        const pinned = saved.rules.find((r) => r.rule_id === rule.id)?.feed
          ?.revision;
        const current = available.some((r) => r.id === rule.id);
        return `<article class="feed-candidate" data-community-item data-search="${esc([rule.spec.name, rule.pack, ...(rule.cves || []), ...(rule.metadata?.technology || [])].join(" ").toLowerCase())}"><label class="check"><input type="checkbox" data-community-rule value="${rule.id}" ${selected.has(rule.id) ? "checked" : ""}><span>${esc(rule.spec.name)}<small>${esc((rule.cves || []).join(", "))} · ${current ? `available r${rule.revision}` : "Source unavailable; frozen copy"}${pinned ? ` · pinned r${pinned}` : ""}</small></span></label>${rule.metadata ? `<details class="advanced"><summary>Coverage and compatibility</summary><p><strong>Affected versions:</strong> ${esc(rule.metadata.affected_versions)}</p><p>${esc(rule.metadata.coverage)}</p><p><strong>Compatibility:</strong> ${esc(rule.metadata.false_positive_risk)}</p><p><strong>Limits:</strong> ${esc(rule.metadata.limitations)}</p>${rule.metadata.references.map((url) => `<p><a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(url)}</a></p>`).join("")}</details>` : ""}</article>`;
      })
      .join("") ||
    '<p>No catalogue rules available. Configure or sync a source in <a href="#rule-feeds">Rule feeds</a>.</p>'
  }</div><small data-community-count></small><label class="check"><input type="checkbox" name="community_refresh"><span>Refresh selected mitigation snapshots</span></label><small>All available selects the current catalogue. Feed sync alone never changes a published policy.</small></div></section>`;
}
export function mountCommunity(
  form: HTMLFormElement,
  available: CommunityRule[],
) {
  const root = form.querySelector<HTMLElement>("[data-community]")!;
  const enabled = root.querySelector<HTMLInputElement>(
    '[name="community_enabled"]',
  )!;
  const all = root.querySelector<HTMLInputElement>("[data-community-all]")!;
  const inputs = Array.from(
    root.querySelectorAll<HTMLInputElement>("[data-community-rule]"),
  );
  const availableIDs = new Set(available.map((r) => r.id));
  const update = () => {
    root.querySelector<HTMLElement>("[data-community-options]")!.hidden =
      !enabled.checked;
    const availableInputs = inputs.filter((i) =>
      availableIDs.has(Number(i.value)),
    );
    const selected = availableInputs.filter((i) => i.checked).length;
    all.checked =
      !!availableInputs.length && selected === availableInputs.length;
    all.indeterminate = selected > 0 && selected < availableInputs.length;
    all.disabled = !availableInputs.length;
    root.querySelector("[data-community-count]")!.textContent =
      `${inputs.filter((i) => i.checked).length} selected`;
  };
  enabled.onchange = update;
  inputs.forEach((i) => (i.onchange = update));
  all.onchange = () => {
    inputs
      .filter((i) => availableIDs.has(Number(i.value)))
      .forEach((i) => (i.checked = all.checked));
    update();
  };
  root.querySelector<HTMLInputElement>("[data-community-search]")!.oninput = (
    event,
  ) => {
    const query = (event.target as HTMLInputElement).value.trim().toLowerCase();
    root
      .querySelectorAll<HTMLElement>("[data-community-item]")
      .forEach((row) => (row.hidden = !row.dataset.search!.includes(query)));
  };
  update();
  return () => ({
    enabled: enabled.checked,
    rule_ids: inputs.filter((i) => i.checked).map((i) => Number(i.value)),
  });
}
