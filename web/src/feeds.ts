type Source = {
  id: number;
  name: string;
  url: string;
  site_id: number;
  last_attempt: string | null;
  last_success: string | null;
  next_sync: string;
  error: string;
  candidates: number;
  pending: number;
};
type Candidate = {
  entry_id: string;
  spec: { name: string; all: unknown[] };
  available: boolean;
  rule_id: number | null;
  pending: boolean;
};
type Context = {
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
        "Rule feeds",
        "Subscribe to simple JSON signatures. Check for updates every 12 hours, or sync whenever you need.",
        button("add-feed", "Add source"),
      ) +
      `<div class="info-panel"><h3>Review before activation</h3><p>Sync downloads candidates. Import creates application-scoped drafts for you to review and observe. Feed changes never replace enabled rules or turn on blocking.</p></div>` +
      (sources.length
        ? c.table(
            ["Source", "Application", "Sync status", "Rules", ""],
            sources.map((s) => [
              `<strong>${esc(s.name)}</strong><small class="domain">${esc(s.url)}</small>`,
              esc(
                c.sites().find((site) => site.id === s.site_id)?.name ||
                  s.site_id,
              ),
              `<span>${s.error ? "Needs attention" : s.last_success ? "Up to date" : "Queued"}</span>${s.error ? `<small class="error-text">${esc(s.error)}</small>` : ""}<small>Last success: ${esc(date(s.last_success))}</small><small>Next check: ${esc(date(s.next_sync))}</small>`,
              `<strong>${s.candidates} available</strong><small>${s.pending} pending import</small>`,
              `<div class="row-actions">${button("sync-feed", "Sync now", s.id)}${button("review-feed", "Review", s.id)}${button("remove-feed", "Remove", s.id)}</div>`,
            ]),
            "Rule sources",
          )
        : '<section class="empty-state"><h2>No rule sources yet</h2><p>Add a public HTTPS JSON feed and choose the application it protects.</p></section>') +
      `<section class="section"><h2>Aegis starter rules</h2><p class="muted">A small set of example signatures for exposed configuration files, Git metadata and common scanner user agents. These are starting points to review for your application.</p>${button("starter-feed", "Use Aegis starter feed")}<p><a href="${starter}" target="_blank" rel="noreferrer">View the starter document</a></p></section>`
    );
  }
  function add(starterFeed = false) {
    if (!c.sites().length) {
      c.notice("Add a proxy host before subscribing to a rule feed.", true);
      return;
    }
    c.openEditor(
      "Add rule source",
      `<form id="feed-form"><label class="field">Name<input name="name" maxlength="120" required value="${starterFeed ? "Aegis starter rules" : ""}" placeholder="My rule source"></label><label class="field">Feed URL<input name="url" type="url" required maxlength="2048" value="${starterFeed ? starter : ""}" placeholder="https://example.com/aegis-rules.json"></label><label class="field" for="feed-site">Application</label><select id="feed-site" name="site_id">${c
        .sites()
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join(
          "",
        )}</select><p class="muted">Public HTTPS only. Aegis supports its version 1 JSON feed format; ModSecurity, IP lists and vendor-specific rule files need conversion. Sync is coordinated across replicas and checks every 12 hours. The first check runs within 30 seconds, or use Sync now.</p><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Add source">Add source</button></div></form>`,
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
        "Source added. Its first sync is queued; imported rules require review and activation.",
      );
    });
  }
  async function review(id: number) {
    const source = sources.find((s) => s.id === id);
    if (!source) return;
    const items = await api<Candidate[]>(`/rule-feeds/${id}/items`);
    c.openEditor(
      source.name,
      `<p class="muted">New and changed candidates can be imported as drafts. Existing local rules remain unchanged, including rules that were imported previously. Disable older rules yourself after reviewing a replacement.</p>${items.length ? items.map((item) => `<article class="feed-candidate"><strong>${esc(item.spec.name)}</strong><small>${esc(item.entry_id)} · ${!item.available ? "Removed from source" : item.pending ? "Pending import" : "Imported"}${item.rule_id ? ` · local rule #${item.rule_id}` : ""}</small><details class="advanced"><summary>View rule JSON</summary><pre>${esc(JSON.stringify(item.spec, null, 2))}</pre></details></article>`).join("") : "<p>No candidates available. Sync the source first.</p>"}<div class="form-actions">${button("cancel", "Close")}${items.some((item) => item.available && item.pending) ? button("import-feed", "Import pending as drafts", id) : ""}</div>`,
    );
  }
  async function handle(action: string | undefined, id: number) {
    switch (action) {
      case "add-feed":
        add();
        return true;
      case "starter-feed":
        add(true);
        return true;
      case "sync-feed":
        await api(`/rule-feeds/${id}/sync`, "POST", {});
        await c.refresh();
        c.notice("Source synced. Review pending candidates before importing.");
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
          confirm("Remove this source? Previously imported rules will be kept.")
        ) {
          await api(`/rule-feeds/${id}`, "DELETE");
          await c.refresh();
          c.notice("Source removed. Imported rules are unchanged.");
        }
        return true;
      default:
        return false;
    }
  }
  return { render, handle };
}
