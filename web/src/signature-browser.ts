export type SignatureEntry = {
  id: number;
  name: string;
  has_message?: boolean;
  category: string;
  severity: string;
  phase: number;
  paranoia_level: number;
  tags: string[];
  source: string;
  scope: "request" | "setup" | "response";
  selectable?: boolean;
};
export type SignatureInventory = { rules: SignatureEntry[] };
type Context = {
  api: <T>(path: string) => Promise<T>;
  esc: (value: unknown) => string;
  exclusions?: HTMLInputElement;
  selection?: Set<number>;
  selectionLimit?: number;
  onSelectionChange?: () => void;
};

const browserLifetimes = new WeakMap<HTMLElement, AbortController>();
export function clearSignatureBrowser(host: HTMLElement) {
  browserLifetimes.get(host)?.abort();
  browserLifetimes.delete(host);
  host.innerHTML = "";
}

export async function mountSignatureBrowser(
  host: HTMLElement,
  setID: string,
  c: Context,
) {
  clearSignatureBrowser(host);
  const lifetime = new AbortController();
  browserLifetimes.set(host, lifetime);
  const options = { signal: lifetime.signal };
  const inventory = await c.api<SignatureInventory>(
    `/signature-sets/${encodeURIComponent(setID)}/rules`,
  );
  if (lifetime.signal.aborted || !host.isConnected) return;
  const { esc } = c;
  const hasChoice = !!c.exclusions || !!c.selection;
  const categories = [
    ...new Set(inventory.rules.map((rule) => rule.category)),
  ].sort();
  const requestCount = inventory.rules.filter(
    (rule) => rule.scope === "request",
  ).length;
  host.innerHTML = `<p class="muted">${inventory.rules.length} bundle entries · ${requestCount} request rules. Response rules run only when enabled in the policy. Setup entries configure the engine. Paranoia level and policy exclusions also determine which request rules run.</p><div class="signature-filters"><label class="field">Search signatures<input type="search" data-signature-search placeholder="Rule ID, description or tag"></label><label class="field">Category<select aria-label="Category" data-signature-category><option value="">All categories</option>${categories.map((category) => `<option value="${esc(category)}">${esc(category)}</option>`).join("")}</select></label><label class="field">Entry type<select aria-label="Entry type" data-signature-scope><option value="request">Request rules</option><option value="all">All bundle entries</option><option value="setup">Setup</option><option value="response">Response · optional</option></select></label></div>${c.exclusions ? '<p class="muted">Check Exclude to disable a request or response rule in this policy. Changes take effect only when you save the policy. The full set remains selected.</p>' : ""}${c.selection ? '<p class="muted">Select detection rules. Engine setup, scoring and enforcement helpers are retained automatically.</p><div class="row-actions"><button type="button" class="secondary compact" data-signature-select-all>Select matching</button><button type="button" class="secondary compact" data-signature-clear-all>Clear matching</button></div>' : ""}<p data-signature-count role="status"></p><div class="table-wrap" tabindex="0" role="region" aria-label="Signature inventory"><table><thead><tr>${hasChoice ? `<th scope="col">${c.selection ? "Include" : "Exclude"}</th>` : ""}<th scope="col">Rule</th><th scope="col">Category</th><th scope="col">Details</th></tr></thead><tbody></tbody></table></div><div class="signature-pagination"><button type="button" class="secondary compact" data-signature-previous>Previous</button><span data-signature-page></span><button type="button" class="secondary compact" data-signature-next>Next</button></div>`;
  const search = host.querySelector<HTMLInputElement>(
    "[data-signature-search]",
  )!;
  const category = host.querySelector<HTMLSelectElement>(
    "[data-signature-category]",
  )!;
  const scope = host.querySelector<HTMLSelectElement>(
    "[data-signature-scope]",
  )!;
  const body = host.querySelector("tbody")!;
  const count = host.querySelector<HTMLElement>("[data-signature-count]")!;
  const previous = host.querySelector<HTMLButtonElement>(
    "[data-signature-previous]",
  )!;
  const next = host.querySelector<HTMLButtonElement>("[data-signature-next]")!;
  let page = 0;
  const excluded = () =>
    new Set(
      (c.exclusions?.value || "")
        .split(/[\s,]+/)
        .filter(Boolean)
        .map(Number),
    );
  const filteredRules = () => {
    const term = search.value.trim().toLowerCase();
    return inventory.rules.filter(
      (rule) =>
        (scope.value === "all" || rule.scope === scope.value) &&
        (!category.value || category.value === rule.category) &&
        (!term ||
          `${rule.id} ${rule.name} ${rule.category} ${rule.tags.join(" ")}`
            .toLowerCase()
            .includes(term)),
    );
  };
  const draw = () => {
    const filtered = filteredRules();
    const pages = Math.max(1, Math.ceil(filtered.length / 25));
    page = Math.min(page, pages - 1);
    const exclusions = excluded();
    count.textContent = `${filtered.length} matching entries${c.selection ? ` · ${c.selection.size} selected` : c.exclusions ? ` · ${exclusions.size} excluded in this policy` : ""}`;
    body.innerHTML =
      filtered
        .slice(page * 25, page * 25 + 25)
        .map(
          (rule) =>
            `<tr>${c.selection ? `<td>${rule.selectable ? `<input type="checkbox" data-select-signature="${rule.id}" aria-label="Include rule ${rule.id}" ${c.selection.has(rule.id) ? "checked" : ""}>` : '<span class="muted">Retained support</span>'}</td>` : c.exclusions ? `<td>${rule.scope !== "setup" ? `<input type="checkbox" data-exclude-signature="${rule.id}" aria-label="Exclude rule ${rule.id}" ${exclusions.has(rule.id) ? "checked" : ""}>` : '<span class="muted">—</span>'}</td>` : ""}<td><strong>#${rule.id} · ${esc(rule.name)}</strong><small>${esc(rule.scope === "response" ? "Response · optional" : rule.scope === "setup" ? "Engine setup" : "Request rule")}</small></td><td>${esc(rule.category)}<small>${rule.paranoia_level ? `Paranoia ${rule.paranoia_level}` : "All paranoia levels"}</small></td><td>${esc(rule.severity)} · phase ${rule.phase}<details><summary>Metadata</summary><small>${esc(rule.source)}</small><small>${esc(rule.tags.join(", "))}</small></details></td></tr>`,
        )
        .join("") ||
      `<tr><td colspan="${hasChoice ? 4 : 3}" class="muted">No signatures match these filters.</td></tr>`;
    previous.disabled = page === 0;
    next.disabled = page + 1 >= pages;
    host.querySelector<HTMLElement>("[data-signature-page]")!.textContent =
      `Page ${page + 1} of ${pages}`;
  };
  search.addEventListener(
    "input",
    () => {
      page = 0;
      draw();
    },
    options,
  );
  category.addEventListener(
    "change",
    () => {
      page = 0;
      draw();
    },
    options,
  );
  scope.addEventListener(
    "change",
    () => {
      page = 0;
      draw();
    },
    options,
  );
  previous.addEventListener(
    "click",
    () => {
      page--;
      draw();
    },
    options,
  );
  next.addEventListener(
    "click",
    () => {
      page++;
      draw();
    },
    options,
  );
  for (const [selector, include] of [
    ["[data-signature-select-all]", true],
    ["[data-signature-clear-all]", false],
  ] as const) {
    host.querySelector(selector)?.addEventListener(
      "click",
      () => {
        const matching = filteredRules().filter((rule) => rule.selectable);
        if (
          include &&
          c.selection &&
          new Set([...c.selection, ...matching.map((rule) => rule.id)]).size >
            (c.selectionLimit ?? Infinity)
        ) {
          count.textContent = `Select at most ${c.selectionLimit} detection rules.`;
          return;
        }
        for (const rule of matching)
          if (rule.selectable) {
            if (include) c.selection?.add(rule.id);
            else c.selection?.delete(rule.id);
          }
        c.onSelectionChange?.();
        draw();
      },
      options,
    );
  }
  host.addEventListener(
    "change",
    (event) => {
      const selectionBox = (
        event.target as HTMLElement
      ).closest<HTMLInputElement>("[data-select-signature]");
      if (selectionBox && c.selection) {
        const id = Number(selectionBox.dataset.selectSignature);
        if (
          selectionBox.checked &&
          !c.selection.has(id) &&
          c.selection.size >= (c.selectionLimit ?? Infinity)
        ) {
          selectionBox.checked = false;
          count.textContent = `Select at most ${c.selectionLimit} detection rules.`;
          return;
        }
        if (selectionBox.checked) c.selection.add(id);
        else c.selection.delete(id);
        c.onSelectionChange?.();
        count.textContent = `${filteredRules().length} matching entries · ${c.selection.size} selected`;
        return;
      }
      const checkbox = (event.target as HTMLElement).closest<HTMLInputElement>(
        "[data-exclude-signature]",
      );
      if (!checkbox || !c.exclusions) return;
      const ids = excluded();
      const id = Number(checkbox.dataset.excludeSignature);
      if (checkbox.checked) {
        if (ids.size >= 100 && !ids.has(id)) {
          checkbox.checked = false;
          count.textContent = "At most 100 rule exclusions are supported.";
          return;
        }
        ids.add(id);
      } else ids.delete(id);
      c.exclusions.value = [...ids].sort((a, b) => a - b).join(", ");
      count.textContent = `${ids.size} excluded in this policy · save the policy to publish changes`;
    },
    options,
  );
  c.exclusions?.addEventListener("input", draw, options);
  draw();
}
