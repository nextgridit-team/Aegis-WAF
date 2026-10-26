import { ruleTabs } from "./rule-tabs";
type Source = {
  id: number;
  name: string;
  url: string;
  site_id: number | null;
  last_attempt: string | null;
  last_success: string | null;
  next_sync: string;
  error: string;
  candidates: number;
  pending: number;
};
type Candidate = {
  catalog_id?: number;
  revision?: number;
  metadata?: {
    pack: string;
    cves: string[];
    technology: string[];
    description: string;
    affected_versions: string;
    coverage: string;
    limitations: string;
    false_positive_risk: string;
    references: string[];
  };
  policies?: {
    id: number;
    name: string;
    revision: number;
    update_available: boolean;
  }[];
  entry_id: string;
  spec: { name: string; all: unknown[] };
  available: boolean;
  rule_id: number | null;
  pending: boolean;
};
type Context = {
  applyToPolicy: (ids: number[], name: string) => Promise<void>;
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  sites: () => { id: number; name: string }[];
  esc: (v: unknown) => string;
  heading: (title: string, text: string, buttons?: string) => string;
  table: (headers: string[], rows: string[][], label: string) => string;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (f: FormData) => Promise<void>) => void;
  refresh: () => Promise<void>;
  notice: (message: string, error?: boolean) => void;
};
const starter =
  "https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/starter.json";
const community =
  "https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/community/manifest.json";
export function makeFeedsUI(c: Context) {
  const { api, esc } = c;
  let sources: Source[] = [];
  const button = (action: string, label: string, id?: number) =>
    `<button type="button" class="secondary compact" data-action="${action}" ${id ? `data-id="${id}"` : ""}>${label}</button>`;
  const date = (value: string | null) =>
    value ? new Date(value).toLocaleString() : "Not yet";
  async function render() {
    sources = await api<Source[]>("/rule-feeds");
    return (
      c.heading(
        "Rules",
        "Subscribe to simple JSON signatures. Check for updates every 12 hours, or sync whenever you need.",
        button("add-feed", "Add source"),
      ) +
      ruleTabs(true) +
      `<div class="info-panel"><h3>Review before activation</h3><p>Sync downloads candidates. Workspace feeds populate a shared catalogue; select individual rules or packs for policy groups. Legacy application feeds import disabled drafts. Feed changes never replace enabled rules or turn on blocking.</p></div>` +
      (sources.length
        ? c.table(
            ["Source", "Scope", "Sync status", "Rules", ""],
            sources.map((s) => [
              `<strong>${esc(s.name)}</strong><small class="domain">${esc(s.url)}</small>`,
              esc(
                !s.site_id
                  ? "Workspace catalogue"
                  : c.sites().find((site) => site.id === s.site_id)?.name ||
                      s.site_id,
              ),
              `<span>${s.error ? "Needs attention" : s.last_success ? "Up to date" : "Queued"}</span>${s.error ? `<small class="error-text">${esc(s.error)}</small>` : ""}<small>Last success: ${esc(date(s.last_success))}</small><small>Next check: ${esc(date(s.next_sync))}</small>`,
              `<strong>${s.candidates} available</strong><small>${s.site_id ? `${s.pending} pending import` : "Select rules for policies"}</small>`,
              `<div class="row-actions">${button("sync-feed", "Sync now", s.id)}${button("review-feed", "Review", s.id)}${button("remove-feed", "Remove", s.id)}</div>`,
            ]),
            "Rule sources",
          )
        : '<section class="empty-state"><h2>No rule sources yet</h2><p>Add a public HTTPS manifest to share independently versioned rules across policies.</p></section>') +
      `<section class="section"><h2>Aegis community mitigation feed</h2><p class="muted">Independent CVE-labelled rules with checksums, revisions, regression cases and explicit partial-mitigation limits. Select only rules compatible with each application.</p>${button("community-feed", "Use Aegis community feed")}<p><a href="${community}" target="_blank" rel="noreferrer">View the manifest</a></p></section><section class="section"><h2>Aegis starter rules</h2><p class="muted">A small set of example signatures for exposed configuration files, Git metadata and common scanner user agents. These are starting points to review for your application.</p>${button("starter-feed", "Use Aegis starter feed")}<p><a href="${starter}" target="_blank" rel="noreferrer">View the starter document</a></p></section>`
    );
  }
  function add(starterFeed = false, communityFeed = false) {
    if (starterFeed && !c.sites().length) {
      c.notice("Add a proxy host before subscribing to a rule feed.", true);
      return;
    }
    c.openEditor(
      "Add rule source",
      `<form id="feed-form"><label class="field">Name<input name="name" maxlength="120" required value="${starterFeed ? "Aegis starter rules" : communityFeed ? "Aegis community mitigations" : ""}" placeholder="My rule source"></label><label class="field">Feed URL<input name="url" type="url" required maxlength="2048" value="${starterFeed ? starter : communityFeed ? community : ""}" placeholder="https://example.com/aegis-rules.json"></label><label class="field" for="feed-site">Application</label><select id="feed-site" name="site_id"><option value="0" ${!starterFeed ? "selected" : ""}>Workspace catalogue · all policies (manifest v2)</option>${c
        .sites()
        .map(
          (s) =>
            `<option value="${s.id}" ${starterFeed && s.id === c.sites()[0]?.id ? "selected" : ""}>${esc(s.name)} · legacy v1</option>`,
        )
        .join(
          "",
        )}</select><p class="muted">Public HTTPS only. Workspace catalogues use a version 2 manifest pointing to individual checksummed rule files. Application-bound sources retain legacy version 1 JSON imports. ModSecurity and vendor formats need conversion. Sync is coordinated across replicas and checks every 12 hours. The first check runs within 30 seconds, or use Sync now.</p><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Add source">Add source</button></div></form>`,
    );
    c.formHandler("feed-form", async (f) => {
      await api("/rule-feeds", "POST", {
        name: f.get("name"),
        url: f.get("url"),
        site_id: Number(f.get("site_id")),
      });
      c.closeEditor();
      await c.refresh();
      c.notice(
        "Source added. Its first sync is queued; review rules before applying them.",
      );
    });
  }
  async function review(id: number) {
    const source = sources.find((s) => s.id === id);
    if (!source) return;
    const items = await api<Candidate[]>(`/rule-feeds/${id}/items`);
    if (!source.site_id) {
      catalogueReview(source, items);
      return;
    }
    c.openEditor(
      source.name,
      `<p class="muted">New and changed candidates can be imported as drafts. Existing local rules remain unchanged, including rules that were imported previously. Disable older rules yourself after reviewing a replacement.</p>${items.length ? items.map((item) => `<article class="feed-candidate"><strong>${esc(item.spec.name)}</strong><small>${esc(item.entry_id)} · ${!item.available ? "Removed from source" : item.pending ? "Pending import" : "Imported"}${item.rule_id ? ` · local rule #${item.rule_id}` : ""}</small><details class="advanced"><summary>View rule JSON</summary><pre>${esc(JSON.stringify(item.spec, null, 2))}</pre></details></article>`).join("") : "<p>No candidates available. Sync the source first.</p>"}<div class="form-actions">${button("cancel", "Close")}${items.some((item) => item.available && item.pending) ? button("import-feed", "Import pending as drafts", id) : ""}</div>`,
    );
  }
  function catalogueReview(source: Source, items: Candidate[]) {
    c.openEditor(
      source.name,
      `<p class="muted">Select individual rules or a pack, review compatibility risks, then configure a policy. Sync updates this catalogue; published policy copies stay pinned.</p><label class="field">Find rules<input type="search" data-catalog-search aria-label="Find catalogue rules" placeholder="CVE, technology or rule name"></label><div data-catalog-items>${items.map((item) => `<article class="feed-candidate" data-catalog-item data-search="${esc([item.spec.name, item.entry_id, item.metadata?.pack, ...(item.metadata?.cves || []), ...(item.metadata?.technology || [])].join(" ").toLowerCase())}"><label class="check"><input type="checkbox" data-catalog-rule value="${item.catalog_id}" ${!item.available ? "disabled" : ""}><span><strong>${esc(item.spec.name)}</strong> <small>r${item.revision} · ${item.available ? "Available" : "Removed from feed"}</small></span></label><small>${esc(item.metadata?.pack)} · ${esc((item.metadata?.cves || []).join(", "))}</small><p>${esc(item.metadata?.description)}</p><p><strong>Compatibility:</strong> ${esc(item.metadata?.false_positive_risk)}</p><small>${(item.policies || []).map((p) => `${esc(p.name)}: pinned r${p.revision}${p.update_available ? " · Update available" : ""}`).join(" · ") || "Not yet applied to a policy"}</small><details class="advanced"><summary>Coverage, advisories and rule definition</summary><p><strong>Affected versions:</strong> ${esc(item.metadata?.affected_versions)}</p><p><strong>Coverage:</strong> ${esc(item.metadata?.coverage)}</p><p><strong>Limits:</strong> ${esc(item.metadata?.limitations)}</p>${(item.metadata?.references || []).map((url) => `<p><a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(url)}</a></p>`).join("")}<pre>${esc(JSON.stringify(item.spec, null, 2))}</pre></details></article>`).join("") || "<p>Sync this source to load catalogue rules.</p>"}</div><p data-catalog-empty hidden>No rules match your search.</p><div class="form-actions">${[...new Set(items.filter((i) => i.available).map((i) => i.metadata?.pack || "Rules"))].map((pack) => `<button type="button" class="secondary compact" data-catalog-pack="${esc(pack)}">Select ${esc(pack)}</button>`).join("")}</div><div class="form-actions"><span data-catalog-count>0 selected</span><button type="button" class="secondary" data-action="cancel">Close</button><button type="button" class="primary" data-catalog-apply disabled>Apply selected to policy</button></div>`,
    );
    const dialog = document.getElementById("editor")!;
    const apply = dialog.querySelector<HTMLButtonElement>(
      "[data-catalog-apply]",
    )!;
    const chosen = () =>
      Array.from(
        dialog.querySelectorAll<HTMLInputElement>(
          "[data-catalog-rule]:checked",
        ),
      ).map((input) => Number(input.value));
    const update = () => {
      const ids = chosen();
      apply.disabled = !ids.length;
      dialog.querySelector("[data-catalog-count]")!.textContent =
        `${ids.length} selected`;
    };
    dialog
      .querySelectorAll<HTMLInputElement>("[data-catalog-rule]")
      .forEach((input) => (input.onchange = update));
    dialog.querySelectorAll<HTMLButtonElement>("[data-catalog-pack]").forEach(
      (button) =>
        (button.onclick = () => {
          for (const item of items)
            if (
              item.available &&
              (item.metadata?.pack || "Rules") === button.dataset.catalogPack
            )
              dialog.querySelector<HTMLInputElement>(
                `[data-catalog-rule=""][value="${item.catalog_id}"]`,
              )!.checked = true;
          update();
        }),
    );
    dialog.querySelector<HTMLInputElement>("[data-catalog-search]")!.oninput = (
      event,
    ) => {
      const query = (event.target as HTMLInputElement).value
        .trim()
        .toLowerCase();
      let visible = 0;
      dialog
        .querySelectorAll<HTMLElement>("[data-catalog-item]")
        .forEach((row) => {
          row.hidden = !row.dataset.search!.includes(query);
          if (!row.hidden) visible++;
        });
      dialog.querySelector<HTMLElement>("[data-catalog-empty]")!.hidden =
        !!visible;
    };
    apply.onclick = async () => {
      apply.disabled = true;
      try {
        const ids = chosen();
        const packs = new Set(
          items
            .filter((item) => ids.includes(item.catalog_id!))
            .map((item) => item.metadata?.pack),
        );
        await c.applyToPolicy(
          ids,
          packs.size === 1 ? [...packs][0] || source.name : source.name,
        );
      } catch (error) {
        c.notice(
          error instanceof Error ? error.message : "Could not configure policy",
          true,
        );
      } finally {
        apply.disabled = false;
      }
    };
  }
  async function handle(action: string | undefined, id: number) {
    switch (action) {
      case "add-feed":
        add();
        return true;
      case "community-feed": {
        const existing = sources.find(
          (source) => !source.site_id && source.url === community,
        );
        if (existing) {
          if (!existing.candidates) {
            await api(`/rule-feeds/${existing.id}/sync`, "POST", {});
            await c.refresh();
          }
          await review(existing.id);
        } else add(false, true);
        return true;
      }
      case "starter-feed":
        add(true);
        return true;
      case "sync-feed":
        await api(`/rule-feeds/${id}/sync`, "POST", {});
        await c.refresh();
        c.notice(
          sources.find((source) => source.id === id)?.site_id
            ? "Source synced. Review pending candidates before importing."
            : "Source synced. Review catalogue rules and pinned policy updates.",
        );
        return true;
      case "review-feed":
        await review(id);
        return true;
      case "import-feed": {
        const result = await api<{ rule_ids: number[] }>(
          `/rule-feeds/${id}/import`,
          "POST",
          {},
        );
        c.closeEditor();
        await c.refresh();
        c.notice(
          `${result.rule_ids.length} draft rules imported. Open Rules to review, observe and activate them.`,
        );
        return true;
      }
      case "remove-feed":
        if (
          confirm("Remove this source? Published policy snapshots and previously imported rules will be kept.")
        ) {
          await api(`/rule-feeds/${id}`, "DELETE");
          await c.refresh();
          c.notice("Source removed. Published policies and imported rules are unchanged.");
        }
        return true;
      default:
        return false;
    }
  }
  return { render, handle };
}
