import {
  clearSignatureBrowser,
  mountSignatureBrowser,
} from "./signature-browser";
type Exception = {
  rule_ids: number[];
  path_prefix?: string;
  parameters?: string[];
  client_cidrs?: string[];
  [key: string]: unknown;
};
type Context = {
  api: <T>(path: string) => Promise<T>;
  esc: (value: unknown) => string;
};
const split = (value: string) => value.split(/[\s,]+/).filter(Boolean);
export function mountPolicyExceptions(form: HTMLFormElement, c: Context) {
  const raw = form.elements.namedItem(
    "signature_scoped_exclusions",
  ) as HTMLTextAreaElement;
  const label = raw.closest("label")!;
  const originalHelp = label.nextElementSibling;
  const root = document.createElement("section");
  root.className = "policy-exceptions-editor";
  root.innerHTML =
    '<h4>Scoped rule exceptions</h4><p class="muted">Exclude selected rules only for a path, request parameter or verified client range. Filled conditions apply together.</p><div data-exception-rows></div><button type="button" class="secondary compact" data-add-exception>Add scoped exception</button><p data-exception-status role="status"></p>';
  const exact = document.createElement("details");
  exact.className = "advanced";
  const summary = document.createElement("summary");
  summary.textContent = "Edit scoped exclusions as JSON";
  exact.append(summary);
  label.before(root);
  exact.append(label);
  if (originalHelp?.tagName === "SMALL") exact.append(originalHelp);
  root.append(exact);
  const rows = root.querySelector<HTMLElement>("[data-exception-rows]")!;
  const status = root.querySelector<HTMLElement>("[data-exception-status]")!;
  const add = root.querySelector<HTMLButtonElement>("[data-add-exception]")!;
  type Row = { value: Exception; node: HTMLFieldSetElement };
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
      row.node.querySelector("legend")!.textContent = "Exception " + (i + 1);
      row.node
        .querySelector("[data-exception-remove]")!
        .setAttribute("aria-label", "Remove exception " + (i + 1));
    });
    add.disabled = state.length >= 32;
    status.textContent = `${state.length} / 32 scoped exceptions. Changes apply when the policy is saved.`;
  };
  const addRow = (value: Exception) => {
    const node = document.createElement("fieldset");
    node.className = "policy-exception-row";
    node.innerHTML =
      '<legend>Scoped exception</legend><div class="policy-exception-grid"><label class="field">Signature rule IDs<input data-exception-ids required placeholder="942100"></label><label class="field">Request path prefix<input data-exception-path maxlength="1024" placeholder="/search"></label><label class="field">Request parameters<input data-exception-parameters placeholder="q, search"></label><label class="field">Client IP ranges<textarea data-exception-clients rows="2" placeholder="192.168.10.0/24"></textarea></label></div><small data-exception-description></small><div class="row-actions"><button type="button" class="secondary compact" data-exception-pick>Choose rules</button><button type="button" class="subtle compact" data-exception-remove>Remove exception</button></div><div data-exception-browser hidden></div>';
    const ids = node.querySelector<HTMLInputElement>("[data-exception-ids]")!,
      path = node.querySelector<HTMLInputElement>("[data-exception-path]")!,
      parameters = node.querySelector<HTMLInputElement>(
        "[data-exception-parameters]",
      )!,
      clients = node.querySelector<HTMLTextAreaElement>(
        "[data-exception-clients]",
      )!;
    ids.value = value.rule_ids.join(", ");
    path.value = value.path_prefix || "";
    parameters.value = (value.parameters || []).join(", ");
    clients.value = (value.client_cidrs || []).join("\n");
    const row: Row = { value: structuredClone(value), node };
    state.push(row);
    rows.append(node);
    const validate = (save: boolean) => {
      const ruleIDs = split(ids.value).map(Number),
        params = split(parameters.value),
        cidrs = split(clients.value);
      const badIDs =
        !ruleIDs.length ||
        ruleIDs.length > 20 ||
        ruleIDs.some(
          (id) =>
            !Number.isInteger(id) ||
            !((id >= 910000 && id < 949000) || (id >= 950000 && id < 959000)),
        );
      ids.setCustomValidity(
        badIDs
          ? "Choose 1–20 request or response detection rule IDs; setup and scoring IDs cannot be scoped out."
          : "",
      );
      path.setCustomValidity(
        !path.value && !params.length && !cidrs.length
          ? "Limit this exception by a path, parameter or client range."
          : path.value && !path.value.startsWith("/")
            ? "Use a request path prefix beginning with /."
            : "",
      );
      parameters.setCustomValidity(
        params.length > 16
          ? "At most 16 parameter names per exception."
          : params.length && ruleIDs.some((id) => id >= 950000)
            ? "Response rules support path/client scopes, not request parameters."
            : "",
      );
      clients.setCustomValidity(
        cidrs.length > 16 ? "At most 16 client ranges per exception." : "",
      );
      const valid = [ids, path, parameters, clients].every(
        (field) => field.validity.valid,
      );
      node.querySelector<HTMLElement>(
        "[data-exception-description]",
      )!.textContent = valid
        ? `Rules ${ruleIDs.map((id) => "#" + id).join(", ")} · ${path.value || "all paths"}${params.length ? " · parameters " + params.join(", ") : ""}${cidrs.length ? " · " + cidrs.length + " client ranges" : ""}`
        : "Choose rules and at least one condition. Other rules and request fields remain inspected.";
      if (save && valid) {
        const next: Exception = { ...row.value, rule_ids: ruleIDs };
        for (const [key, v] of [
          ["path_prefix", path.value],
          ["parameters", params],
          ["client_cidrs", cidrs],
        ] as const) {
          if (v.length || Object.hasOwn(row.value, key))
            Object.assign(next, { [key]: v });
          else delete next[key];
        }
        row.value = next;
        serialize();
      }
    };
    node.addEventListener("input", () => {
      validate(true);
    });
    node
      .querySelector<HTMLButtonElement>("[data-exception-remove]")!
      .addEventListener("click", () => {
        const host = node.querySelector<HTMLElement>(
          "[data-exception-browser]",
        )!;
        clearSignatureBrowser(host);
        state = state.filter((item) => item !== row);
        node.remove();
        serialize();
        updateCount();
        add.focus();
      });
    node
      .querySelector<HTMLButtonElement>("[data-exception-pick]")!
      .addEventListener("click", async () => {
        const button = node.querySelector<HTMLButtonElement>(
            "[data-exception-pick]",
          )!,
          host = node.querySelector<HTMLElement>("[data-exception-browser]")!;
        const set = (
          form.elements.namedItem("signature_set") as HTMLSelectElement
        ).value;
        if (!set) {
          status.textContent = "Choose a signature set before browsing rules.";
          return;
        }
        if (!host.hidden) {
          host.hidden = true;
          clearSignatureBrowser(host);
          return;
        }
        button.disabled = true;
        host.hidden = false;
        try {
          const selected = new Set(split(ids.value).map(Number));
          await mountSignatureBrowser(host, set, {
            ...c,
            selection: selected,
            selectionLimit: 20,
            onSelectionChange: () => {
              ids.value = [...selected].sort((a, b) => a - b).join(", ");
              validate(true);
            },
          });
        } catch (error) {
          status.textContent =
            error instanceof Error
              ? error.message
              : "Could not load signature rules.";
        } finally {
          button.disabled = false;
        }
      });
    validate(false);
    updateCount();
    return row;
  };
  const render = () => {
    try {
      const values: unknown = JSON.parse(raw.value || "[]");
      if (
        !Array.isArray(values) ||
        values.length > 32 ||
        values.some(
          (value) =>
            !value ||
            typeof value !== "object" ||
            !Array.isArray(value.rule_ids) ||
            value.rule_ids.some((id: unknown) => typeof id !== "number") ||
            (value.path_prefix !== undefined &&
              typeof value.path_prefix !== "string") ||
            ["parameters", "client_cidrs"].some(
              (key) =>
                value[key] !== undefined &&
                (!Array.isArray(value[key]) ||
                  value[key].some((v: unknown) => typeof v !== "string")),
            ),
        )
      )
        throw new Error(
          "Use an array of up to 32 exceptions with rule_ids and typed path/parameter/client scopes.",
        );
      for (const host of rows.querySelectorAll<HTMLElement>(
        "[data-exception-browser]",
      ))
        clearSignatureBrowser(host);
      rows.replaceChildren();
      state = [];
      raw.setCustomValidity("");
      for (const value of values) addRow(value as Exception);
      updateCount();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Invalid exception JSON.";
      raw.setCustomValidity(message);
      status.textContent = message;
      add.disabled = true;
      for (const row of state) row.node.disabled = true;
    }
  };
  add.addEventListener("click", () => {
    if (state.length >= 32) return;
    const row = addRow({ rule_ids: [] });
    serialize();
    row.node.querySelector<HTMLInputElement>("input")!.focus();
  });
  raw.addEventListener("input", render);
  (
    form.elements.namedItem("signature_set") as HTMLSelectElement
  ).addEventListener("change", () => {
    for (const host of rows.querySelectorAll<HTMLElement>(
      "[data-exception-browser]",
    )) {
      host.hidden = true;
      clearSignatureBrowser(host);
    }
  });
  render();
}
