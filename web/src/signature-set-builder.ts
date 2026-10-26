import {
  mountSignatureBrowser,
  clearSignatureBrowser,
} from "./signature-browser";
import type { SignatureSet } from "./signature-sets";
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  esc: (value: unknown) => string;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
  refresh: () => Promise<void>;
  notice: (message: string, error?: boolean) => void;
};
export async function openSignatureBuilder(
  c: Context,
  sources: SignatureSet[],
  initial?: { source: string; name: string; selected: number[]; note?: string },
) {
  sources = sources.filter((s) => !s.curation);
  if (!sources.length)
    throw new Error(
      "Load an original signature set before creating a curated set.",
    );
  const selected = new Set<number>(initial?.selected || []);
  const { esc } = c;
  c.openEditor(
    "Create curated signature set",
    `<form id="signature-builder-form"><label class="field">Set name<input name="name" maxlength="120" required value="${esc(initial?.name || "")}" placeholder="Public API detection set"></label><label class="field">Source set<select name="source_set_id" aria-label="Source signature set">${sources.map((s) => `<option value="${esc(s.id)}" ${s.id === initial?.source ? "selected" : ""}>${esc(s.name)} ${esc(s.version)}</option>`).join("")}</select></label><p data-source-provenance></p>${initial?.note ? `<p class="info-panel">${esc(initial.note)}</p>` : ""}<p class="info-panel">This saves an immutable selection from one source. Scoring and enforcement helpers stay included. Sparse sets may never accumulate the full CRS anomaly threshold; consider lower thresholds in Observe and test legitimate traffic.</p><div data-curation-browser></div><p data-curation-count role="status"></p><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Save curated set" disabled>Save curated set</button></div></form>`,
  );
  const form = document.getElementById(
    "signature-builder-form",
  ) as HTMLFormElement;
  const source = form.elements.namedItem("source_set_id") as HTMLSelectElement;
  const browser = form.querySelector<HTMLElement>("[data-curation-browser]")!;
  const save = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
  let ready = false;
  let generation = 0;
  const update = () => {
    form.querySelector<HTMLElement>("[data-curation-count]")!.textContent =
      `${selected.size} detection rules selected`;
    save.disabled = !ready || selected.size === 0;
  };
  const load = async () => {
    const current = ++generation;
    ready = false;
    update();
    clearSignatureBrowser(browser);
    const id = source.value;
    const set = sources.find((s) => s.id === id)!;
    form.querySelector<HTMLElement>("[data-source-provenance]")!.textContent =
      `Pinned source: ${set.version} · SHA-256 ${set.digest}`;
    try {
      await mountSignatureBrowser(browser, id, {
        api: c.api,
        esc,
        selection: selected,
        onSelectionChange: update,
      });
      if (current === generation && source.value === id && form.isConnected) {
        ready = true;
        update();
      }
    } catch (error) {
      if (current === generation && form.isConnected)
        c.notice(
          error instanceof Error ? error.message : "Could not load source",
          true,
        );
    }
  };
  source.addEventListener("change", () => {
    selected.clear();
    void load();
  });
  c.formHandler("signature-builder-form", async (f) => {
    if (!ready || selected.size === 0)
      throw new Error("Select at least one detection rule.");
    await c.api<SignatureSet>("/signature-sets", "POST", {
      name: f.get("name"),
      source_set_id: f.get("source_set_id"),
      selected_rule_ids: [...selected].sort((a, b) => a - b),
    });
    c.closeEditor();
    await c.refresh();
    c.notice(
      "Curated set saved. Select it in a policy and start in Observe; existing policies were not changed.",
    );
  });
  await load();
}
