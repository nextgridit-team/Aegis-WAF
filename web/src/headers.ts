export type HeaderSettings = {
  hsts?: {
    enabled: boolean;
    max_age_seconds: number;
    include_subdomains: boolean;
  };
  forwarded_headers: string;
  request_set: Record<string, string>;
  request_remove: string[];
  response_set: Record<string, string>;
  response_remove: string[];
};
const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
function row(side: string, name = "", value = "", remove = false) {
  const label = side === "request" ? "Request" : "Response";
  return `<div class="header-row" data-header-row role="group" aria-label="${label} header"><select data-header-op aria-label="${label} header action"><option value="set" ${!remove ? "selected" : ""}>Set</option><option value="remove" ${remove ? "selected" : ""}>Remove</option></select><input data-header-name aria-label="${label} header name" placeholder="X-Example" value="${esc(name)}" required maxlength="128"><input class="header-value" data-header-value aria-label="${label} header value" placeholder="Header value" value="${esc(value)}" maxlength="4096" ${remove ? "hidden disabled" : ""}><button type="button" class="subtle compact" data-header-delete aria-label="Remove ${label.toLowerCase()} header">Remove</button></div>`;
}
export function headerMarkup(s?: HeaderSettings | null) {
  return `<details class="advanced"><summary>HTTPS security</summary><label class="check"><input type="checkbox" name="hsts_enabled" ${s?.hsts?.enabled ? "checked" : ""}><span>Enforce HSTS</span></label><label class="field">HSTS max age (seconds)<input type="number" name="hsts_max_age" min="0" max="63072000" required value="${s?.hsts?.max_age_seconds ?? 31536000}"></label><label class="check"><input type="checkbox" name="hsts_subdomains" ${s?.hsts?.include_subdomains ? "checked" : ""}><span>Include subdomains in HSTS</span></label><small>Browsers require HTTPS for this hostname after receiving the header over trusted HTTPS. This does not configure upstream certificate trust. Enable subdomains only when all are HTTPS-ready. Disabling this setting does not clear cached browser policies; max age 0 clears this host's policy. No preload directive is added.</small></details><details class="advanced"><summary>Proxy headers</summary><label class="check"><input name="forward_client_headers" type="checkbox" ${s?.forwarded_headers !== "off" ? "checked" : ""}><span>Forward validated client headers to the upstream</span></label><small>Sends X-Forwarded-For, X-Real-IP, X-Forwarded-Host, X-Forwarded-Proto and X-Forwarded-Port using the resolved client identity. Untrusted client-supplied identity headers are discarded.</small>${[
    "request",
    "response",
  ]
    .map((side) => {
      const sets = side === "request" ? s?.request_set : s?.response_set;
      const removes =
        side === "request" ? s?.request_remove : s?.response_remove;
      return `<fieldset class="header-editor" data-header-side="${side}"><legend>${side === "request" ? "Request headers · sent to upstream" : "Response headers · sent to clients"}</legend><div data-header-rows>${Object.entries(
        sets || {},
      )
        .map(([name, value]) => row(side, name, value))
        .join(
          "",
        )}${(removes || []).map((name) => row(side, name, "", true)).join("")}</div><button type="button" class="secondary compact" data-header-add="${side}">Add ${side} header</button></fieldset>`;
    })
    .join(
      "",
    )}<small>Set replaces a header; Remove strips it. Forwarding, Host and transport headers have dedicated controls. Static credential/cookie headers are not supported.</small></details>`;
}
export function bindHeaderEditor(form: HTMLFormElement) {
  const sync = () =>
    form.querySelectorAll<HTMLElement>("[data-header-side]").forEach((side) => {
      side.querySelector<HTMLButtonElement>("[data-header-add]")!.disabled =
        side.querySelectorAll("[data-header-row]").length >= 32;
    });
  form.addEventListener("click", (e) => {
    const target = (e.target as HTMLElement).closest<HTMLElement>(
      "[data-header-add],[data-header-delete]",
    );
    if (!target) return;
    const side = target.closest<HTMLElement>("[data-header-side]")!;
    if (target.hasAttribute("data-header-delete")) {
      target.closest("[data-header-row]")!.remove();
    } else if (side.querySelectorAll("[data-header-row]").length < 32) {
      side
        .querySelector("[data-header-rows]")!
        .insertAdjacentHTML("beforeend", row(side.dataset.headerSide!));
      side
        .querySelector<HTMLElement>(
          "[data-header-row]:last-child [data-header-name]",
        )
        ?.focus();
    }
    sync();
  });
  form.addEventListener("change", (e) => {
    const target = e.target as HTMLElement;
    if (!target.hasAttribute("data-header-op")) return;
    const input = target
      .closest("[data-header-row]")!
      .querySelector<HTMLInputElement>("[data-header-value]")!;
    const remove = (target as HTMLSelectElement).value === "remove";
    input.disabled = remove;
    input.hidden = remove;
  });
  sync();
}
export function readHeaders(form: HTMLFormElement): HeaderSettings {
  const out: HeaderSettings = {
    hsts: {
      enabled: (form.elements.namedItem("hsts_enabled") as HTMLInputElement)
        .checked,
      max_age_seconds: Number(
        (form.elements.namedItem("hsts_max_age") as HTMLInputElement).value,
      ),
      include_subdomains: (
        form.elements.namedItem("hsts_subdomains") as HTMLInputElement
      ).checked,
    },
    forwarded_headers: (
      form.elements.namedItem("forward_client_headers") as HTMLInputElement
    ).checked
      ? "standard"
      : "off",
    request_set: Object.create(null),
    request_remove: [],
    response_set: Object.create(null),
    response_remove: [],
  };
  for (const side of ["request", "response"] as const) {
    const seen = new Set<string>();
    form
      .querySelectorAll<HTMLElement>(
        `[data-header-side="${side}"] [data-header-row]`,
      )
      .forEach((row) => {
        const name = row
          .querySelector<HTMLInputElement>("[data-header-name]")!
          .value.trim();
        if (!name || seen.has(name.toLowerCase()))
          throw new Error(
            "Each custom header needs a unique name within its direction.",
          );
        seen.add(name.toLowerCase());
        const op =
          row.querySelector<HTMLSelectElement>("[data-header-op]")!.value;
        if (op === "remove") out[`${side}_remove`].push(name);
        else
          out[`${side}_set`][name] = row.querySelector<HTMLInputElement>(
            "[data-header-value]",
          )!.value;
      });
  }
  return out;
}
