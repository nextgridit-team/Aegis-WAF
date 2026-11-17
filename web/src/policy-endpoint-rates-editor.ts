type EndpointRate = {
  path_pattern: string;
  match?: string;
  requests_per_second: number;
  burst: number;
  scope?: string;
  [key: string]: unknown;
};
type Context = {
  esc: (value: unknown) => string;
};
// The complete key allowlist for an endpoint rate override. The server
// rejects unknown keys by name; the editor mirrors the same contract so the
// JSON never leaves the form with a misspelled field.
const allowedEndpointRateKeys = new Set([
  "path_pattern",
  "match",
  "requests_per_second",
  "burst",
  "scope",
]);
export function mountPolicyEndpointRates(
  form: HTMLFormElement,
  c: Context,
) {
  const raw = form.elements.namedItem("endpoint_rates") as HTMLTextAreaElement;
  const label = raw.closest("label")!;
  const originalHelp = label.nextElementSibling;
  const root = document.createElement("section");
  root.className = "policy-endpoint-rates-editor";
  root.innerHTML =
    '<h4>Endpoint rate overrides</h4><p class="muted">Tighter budgets for specific paths, evaluated in order with the first matching pattern winning. Overrides apply underneath the per-client and per-application budgets, so they can only tighten a budget.</p><div data-rate-rows></div><button type="button" class="secondary compact" data-add-rate>Add endpoint override</button><p data-rate-status role="status"></p>';
  const exact = document.createElement("details");
  exact.className = "advanced";
  const summary = document.createElement("summary");
  summary.textContent = "Edit endpoint overrides as JSON";
  exact.append(summary);
  label.before(root);
  exact.append(label);
  if (originalHelp?.tagName === "SMALL") exact.append(originalHelp);
  root.append(exact);
  const rows = root.querySelector<HTMLElement>("[data-rate-rows]")!;
  const status = root.querySelector<HTMLElement>("[data-rate-status]")!;
  const add = root.querySelector<HTMLButtonElement>("[data-add-rate]")!;
  type Row = { value: EndpointRate; node: HTMLFieldSetElement };
  let state: Row[] = [];
  const serialize = () => {
    raw.value = JSON.stringify(
      state.map((row) => row.value),
      null,
      2,
    );
    raw.setCustomValidity("");
    raw.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const updateCount = () => {
    state.forEach((row, i) => {
      row.node.querySelector("legend")!.textContent = "Endpoint " + (i + 1);
      row.node
        .querySelector("[data-rate-remove]")!
        .setAttribute("aria-label", "Remove endpoint override " + (i + 1));
    });
    add.disabled = state.length >= 32;
    status.textContent = `${state.length} / 32 endpoint overrides. The first matching pattern applies; changes apply when the policy is saved.`;
  };
  const addRow = (value: EndpointRate) => {
    const node = document.createElement("fieldset");
    node.className = "policy-endpoint-rate-row";
    node.innerHTML =
      '<legend>Endpoint override</legend><div class="policy-exception-grid"><label class="field">Path pattern<input data-rate-path required maxlength="1024" placeholder="/login"></label><label class="field">Match<select data-rate-match aria-label="Match"><option value="prefix">Prefix · /login also covers /login/step</option><option value="exact">Exact · only this path</option></select></label><label class="field">Endpoint requests / second<input data-rate-rate type="number" required min="1" max="100000" step="1" value="10"></label><label class="field">Endpoint burst allowance<input data-rate-burst type="number" required min="1" max="1000000" step="1" value="20"></label><label class="field">Scope<select data-rate-scope aria-label="Scope"><option value="per-client">Per client · each client IP gets this budget</option><option value="site-wide">Site-wide · all clients share this budget</option></select></label></div><small data-rate-description></small><div class="row-actions"><button type="button" class="subtle compact" data-rate-remove>Remove override</button></div>';
    const path = node.querySelector<HTMLInputElement>("[data-rate-path]")!,
      match = node.querySelector<HTMLSelectElement>("[data-rate-match]")!,
      rate = node.querySelector<HTMLInputElement>("[data-rate-rate]")!,
      burst = node.querySelector<HTMLInputElement>("[data-rate-burst]")!,
      scope = node.querySelector<HTMLSelectElement>("[data-rate-scope]")!,
      note = node.querySelector<HTMLElement>("[data-rate-description]")!;
    path.value = value.path_pattern;
    match.value = value.match || "prefix";
    rate.value = String(value.requests_per_second || 10);
    burst.value = String(value.burst || 20);
    scope.value = value.scope || "per-client";
    const row: Row = { value: structuredClone(value), node };
    state.push(row);
    rows.append(node);
    const describe = () => {
      const kind =
        match.value === "exact" ? "exactly this path" : "paths starting with it";
      const shared =
        scope.value === "site-wide"
          ? "shared across every client on the application"
          : "separate per client";
      note.textContent = `Matches ${kind}; the ${rate.value} req/s budget is ${shared}.`;
    };
    const validate = () => {
      const pattern = path.value.trim();
      const r = Number(rate.value),
        b = Number(burst.value);
      if (!pattern.startsWith("/") || pattern.length > 1024) {
        return "Path patterns must start with / and fit 1024 bytes.";
      }
      if (!Number.isInteger(r) || r < 1 || r > 100000) {
        return "Requests / second must be a whole number between 1 and 100000.";
      }
      if (!Number.isInteger(b) || b < r || b > 1000000) {
        return "Burst must be a whole number at least as large as requests / second.";
      }
      return "";
    };
    const sync = () => {
      const problem = validate();
      path.setCustomValidity(problem);
      rate.setCustomValidity(problem);
      burst.setCustomValidity(problem);
      row.value = {
        path_pattern: path.value.trim(),
        match: match.value,
        requests_per_second: Number(rate.value),
        burst: Number(burst.value),
        scope: scope.value,
      };
      describe();
      serialize();
    };
    path.addEventListener("input", sync);
    rate.addEventListener("input", sync);
    burst.addEventListener("input", sync);
    match.addEventListener("change", sync);
    scope.addEventListener("change", sync);
    node
      .querySelector<HTMLButtonElement>("[data-rate-remove]")!
      .addEventListener("click", () => {
        state = state.filter((candidate) => candidate !== row);
        node.remove();
        updateCount();
        serialize();
      });
    sync();
  };
  add.addEventListener("click", () => {
    addRow({
      path_pattern: "",
      match: "prefix",
      requests_per_second: 10,
      burst: 20,
      scope: "per-client",
    });
    updateCount();
    serialize();
    const last = rows.querySelector<HTMLElement>(
      ".policy-endpoint-rate-row:last-child [data-rate-path]",
    );
    last?.focus();
  });
  raw.addEventListener("change", () => {
    let parsed: EndpointRate[] = [];
    try {
      parsed = JSON.parse(raw.value || "[]");
    } catch {
      return;
    }
    if (!Array.isArray(parsed)) return;
    const same =
      parsed.length === state.length &&
      parsed.every((entry, i) =>
        Object.keys(entry)
          .filter((key) => allowedEndpointRateKeys.has(key))
          .every(
            (key) =>
              JSON.stringify(entry[key]) ===
              JSON.stringify((state[i]?.value as Record<string, unknown>)[key]),
          ),
      );
    if (same) return;
    state.forEach((row) => row.node.remove());
    state = [];
    for (const entry of parsed) {
      if (
        entry &&
        typeof entry === "object" &&
        !Array.isArray(entry) &&
        Object.keys(entry).every((key) => allowedEndpointRateKeys.has(key))
      ) {
        addRow({
          path_pattern: String(entry.path_pattern || ""),
          match: entry.match === "exact" ? "exact" : "prefix",
          requests_per_second: Number(entry.requests_per_second) || 1,
          burst: Number(entry.burst) || 1,
          scope: entry.scope === "site-wide" ? "site-wide" : "per-client",
        });
      }
    }
    updateCount();
  });
  for (const entry of (() => {
    try {
      return JSON.parse(raw.value || "[]") as EndpointRate[];
    } catch {
      return [] as EndpointRate[];
    }
  })()) {
    if (
      entry &&
      typeof entry === "object" &&
      Object.keys(entry).every((key) => allowedEndpointRateKeys.has(key))
    ) {
      addRow(entry);
    }
  }
  updateCount();
  serialize();
}
