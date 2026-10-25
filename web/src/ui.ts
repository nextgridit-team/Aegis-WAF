import type { Account } from "./types";
export const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
export const date = (v: string | null) =>
  v
    ? new Date(v).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : "Not issued yet";
export const dateTime = (v: string) => new Date(v).toLocaleString();
export const icons: Record<string, string> = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z M9 12l2 2 4-4",
  certificate:
    "M7 3h10l3 3v9h-4M7 3 4 6v9h4 M8 9h8 M8 6h5 M12 13l2 1 2 1-1 2v4l-3-2-3 2v-4l-1-2 2-1Z",
  globe:
    "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  key: "M14 7a4 4 0 1 1 0 6l-6 6H4v-4l6-6a4 4 0 0 1 4-2Z",
  plus: "M12 5v14M5 12h14",
  arrow: "M5 12h14m-5-5 5 5-5 5",
  close: "m6 6 12 12M6 18 18 6",
  check: "m5 12 4 4L19 6",
  clock: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 7v5l3 2",
  upload: "M12 16V3m-5 5 5-5 5 5M4 15v6h16v-6",
  refresh: "M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3",
  logout: "M9 4H4v16h5M10 12h11m-4-4 4 4-4 4",
};
export const icon = (name: string) =>
  `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${icons[name] || icons.shield}"/></svg>`;
export const button = (
  action: string,
  label: string,
  style = "primary",
  id?: number,
) =>
  `<button type="button" class="${style}" data-action="${action}" ${id ? `data-id="${id}"` : ""}>${label}</button>`;
export const badge = (label: string, tone = "neutral") =>
  `<span class="badge ${tone}"><span class="badge-dot"></span>${esc(label)}</span>`;
export const field = (
  name: string,
  label: string,
  value = "",
  type = "text",
  extra = "",
) =>
  `<label class="field">${label}<input name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;
export const check = (name: string, label: string, checked = false, extra = "") =>
  `<label class="check"><input type="checkbox" name="${name}" ${checked ? "checked" : ""} ${extra}><span>${label}</span></label>`;
export const actions = (label: string) =>
  `<div class="form-actions">${button("cancel", "Cancel", "secondary")}<button type="submit" class="primary" data-label="${label}">${label}${icon("arrow")}</button></div>`;
export const names = (v: FormDataEntryValue | null) =>
  String(v || "")
    .split(/[\s,]+/)
    .filter(Boolean);
export const authority = (a: Account) =>
  a.directory.includes("acme-staging-v02.api.letsencrypt.org")
    ? "Let’s Encrypt · staging"
    : a.directory.includes("acme-v02.api.letsencrypt.org")
      ? "Let’s Encrypt · production"
      : new URL(a.directory).host;
export const heading = (title: string, text: string, buttons = "") =>
  `<div class="page-heading"><div><h1>${title}</h1><p>${text}</p></div><div class="heading-actions">${buttons}</div></div>`;
export function table(headers: string[], rows: string[][], label: string) {
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(label)}"><table><thead><tr>${headers.map((h) => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
