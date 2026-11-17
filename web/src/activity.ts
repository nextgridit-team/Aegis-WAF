import { clientAddress } from "./response-status";
import { managedSignatureSummary } from "./signature-sets";
import { button, dateTime, esc, heading, icon, table } from "./ui";
import type { Access, Audit, Site } from "./types";

/* Activity: investigation history over access logs and the administrative
   audit trail. Filters live in the URL hash (#activity?site_id=2&blocked=true)
   so an investigation view survives reload and sharing; "Load more" follows
   the stable (at,id) cursor so new traffic never shifts the window. */
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  handleError: (error: unknown) => Promise<void>;
};
type AccessPage = { rows: Access[]; next_cursor: string };
type AuditPage = { rows: Audit[]; next_cursor: string };

const accessFilters = [
  { key: "site_id", label: "Application", kind: "site" },
  { key: "blocked", label: "Decision", kind: "decision" },
  { key: "status", label: "Status", kind: "text" },
  { key: "client_ip", label: "Client IP / CIDR", kind: "text" },
  { key: "request_id", label: "Request ID", kind: "text" },
  { key: "host", label: "Host", kind: "text" },
  { key: "rule_id", label: "Rule ID", kind: "text" },
  { key: "policy_id", label: "Policy ID", kind: "text" },
  { key: "path_class", label: "Path class", kind: "text" },
  { key: "from", label: "From", kind: "datetime" },
  { key: "to", label: "To", kind: "datetime" },
] as const;
const auditFilters = [
  { key: "actor", label: "Actor", kind: "text" },
  { key: "action", label: "Action", kind: "text" },
  { key: "from", label: "From", kind: "datetime" },
  { key: "to", label: "To", kind: "datetime" },
] as const;

// datetime-local values are local wall time; the API takes RFC3339 UTC.
function toRFC3339(value: string): string {
  return value ? new Date(value).toISOString() : "";
}
function toLocalInput(value: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function makeActivityPage(c: Context) {
  let accessRows: Access[] = [],
    auditRows: Audit[] = [],
    accessCursor = "",
    auditCursor = "",
    serial = 0,
    sites: Site[] = [],
    currentView: HTMLElement | null = null;

  function params(): URLSearchParams {
    return new URLSearchParams(location.hash.split("?")[1]);
  }
  function filterValue(key: string): string {
    return (params().get(key) || "").trim();
  }
  function buildQuery(
    filters: readonly { key: string }[],
    extra: Record<string, string> = {},
  ): string {
    const values = new URLSearchParams();
    for (const filter of filters) {
      const value = filterValue(filter.key);
      if (value) values.set(filter.key, value);
    }
    for (const [key, value] of Object.entries(extra))
      if (value) values.set(key, value);
    return values.toString();
  }
  function filterInput(
    filter: { key: string; label: string; kind: string },
  ): string {
    const value = filterValue(filter.key);
    if (filter.kind === "site")
      return `<label class="field">${filter.label}<select name="${filter.key}" aria-label="${filter.label}"><option value="">All applications</option>${sites.map((site) => `<option value="${site.id}" ${String(site.id) === value ? "selected" : ""}>${esc(site.name)}</option>`).join("")}</select></label>`;
    if (filter.kind === "decision")
      return `<label class="field">${filter.label}<select name="${filter.key}" aria-label="${filter.label}"><option value="">Allowed and blocked</option><option value="true" ${value === "true" ? "selected" : ""}>Blocked</option><option value="false" ${value === "false" ? "selected" : ""}>Allowed</option></select></label>`;
    if (filter.kind === "datetime")
      return `<label class="field">${filter.label}<input name="${filter.key}" type="datetime-local" value="${esc(toLocalInput(value))}"></label>`;
    return `<label class="field">${filter.label}<input name="${filter.key}" type="text" value="${esc(value)}" placeholder="${filter.key === "client_ip" ? "198.51.100.0/24" : ""}"></label>`;
  }
  function filterForm(
    id: string,
    filters: readonly { key: string; label: string; kind: string }[],
  ): string {
    return `<form id="${id}" class="filter-grid">${filters.map(filterInput).join("")}<div class="filter-actions"><button type="submit" class="secondary">Apply filters</button><button type="button" class="secondary" data-activity-action="clear">Clear</button></div></form>`;
  }
  function applyFilters(form: HTMLFormElement, keys: readonly string[]) {
    const data = new FormData(form);
    const values = new URLSearchParams();
    for (const key of keys) {
      const raw = String(data.get(key) || "").trim();
      if (!raw) continue;
      values.set(key, key === "from" || key === "to" ? toRFC3339(raw) : raw);
    }
    const next = "activity" + (values.toString() ? `?${values}` : "");
    if (location.hash === "#" + next) void render();
    else location.hash = next;
  }
  async function loadMore(page: "access" | "audit") {
    try {
      if (page === "access") {
        const next = await c.api<AccessPage>(
          `/access-logs?${buildQuery(accessFilters, { cursor: accessCursor })}`,
        );
        accessRows = accessRows.concat(next.rows);
        accessCursor = next.next_cursor;
      } else {
        const next = await c.api<AuditPage>(
          `/audit?${buildQuery(auditFilters, { cursor: auditCursor })}`,
        );
        auditRows = auditRows.concat(next.rows);
        auditCursor = next.next_cursor;
      }
      paint();
    } catch (error) {
      await c.handleError(error);
    }
  }

  function auditMarkup(): string {
    return `<section class="section"><div class="section-heading"><h2>Administrative audit</h2><span class="muted">${auditRows.length} events${auditCursor ? " · more available" : ""}</span></div>${
      auditRows.length
        ? table(
            ["Time", "Administrator", "Action", "Resource"],
            auditRows.map((row) => [
              esc(dateTime(row.at)),
              esc(row.actor),
              esc(row.action),
              esc(row.resource),
            ]),
            "Administrative audit",
          )
        : '<div class="simple-empty">No administrative events match these filters.</div>'
    }${auditCursor ? activityButton("audit-load-more") : ""}</section>`;
  }
  function accessMarkup(): string {
    const applied = buildQuery(accessFilters);
    const exportBase = `/api/access-logs/export${applied ? "?" + applied : ""}`;
    const joiner = applied ? "&" : "?";
    return `<section class="section"><div class="section-heading"><h2>Application requests</h2><span class="muted">${accessRows.length} requests${accessCursor ? " · more available" : ""}</span></div>${
      accessRows.length
        ? table(
            ["Time", "Site / sender", "Request", "Rule outcomes", "Duration", ""],
            accessRows.map((row) => [
              esc(dateTime(row.at)),
              `${row.site_id}<div>${clientAddress(row.peer, row.client_objects)}</div>${row.policy_name ? `<small>${esc(row.policy_name)} · v${row.policy_revision}</small>` : ""}${managedSignatureSummary(row.managed_signatures, esc)}`,
              `${esc(row.method)} · ${row.status}`,
              [
                ...(row.rule_results || []).map(
                  (result) =>
                    `#${result.rule_id} · ${esc(result.action)} · ${esc(result.result)}`,
                ),
                ...(row.protection_exemptions || []).map((value) =>
                  esc(
                    value === "http_flood"
                      ? "HTTP flood exempt"
                      : value === "anti_bot"
                        ? "Anti-bot exempt"
                        : value,
                  ),
                ),
              ].join("<br>") || "—",
              `${row.duration_ms} ms`,
              button(
                "request-details",
                "View details",
                "secondary compact",
                row.id,
              ),
            ]),
            "Application requests",
          )
        : '<div class="simple-empty">No requests match these filters.</div>'
    }${accessCursor ? activityButton("access-load-more") : ""}<p class="muted">Export the filtered window as <a href="${exportBase}${joiner}format=csv">CSV</a> or <a href="${exportBase}${joiner}format=json">JSON</a> — bounded to 10,000 rows; larger windows are rejected rather than truncated.</p></section>`;
  }
  function activityButton(name: string): string {
    return `<div class="load-more"><button type="button" class="secondary" data-activity-action="${name}">Load more</button></div>`;
  }

  function paint() {
    if (!currentView || !currentView.isConnected) return;
    currentView.innerHTML =
      heading(
        "Activity",
        "Administrative changes and requests to your applications, filtered by the investigation view.",
        button("refresh", `${icon("refresh")}Refresh`, "secondary"),
      ) +
      auditMarkup() +
      accessMarkup();
    wire();
  }
  function wire() {
    const forms = document.querySelectorAll<HTMLFormElement>(
      "form[id$=-filters]",
    );
    forms.forEach((form) => {
      form.onsubmit = (event) => {
        event.preventDefault();
        const keys =
          form.id === "access-filters"
            ? accessFilters.map((filter) => filter.key)
            : auditFilters.map((filter) => filter.key);
        applyFilters(form, keys);
      };
    });
    if (currentView)
      currentView.onclick = (event) => {
        const target = (event.target as HTMLElement).closest<HTMLButtonElement>(
          "[data-activity-action]",
        );
        if (!target) return;
        const action = target.dataset.activityAction;
        if (action === "clear") {
          if (location.hash === "#activity") void render();
          else location.hash = "activity";
        }
        if (action === "access-load-more" || action === "audit-load-more")
          void loadMore(action === "access-load-more" ? "access" : "audit");
      };
  }

  async function render(view?: HTMLElement, siteList?: Site[]) {
    if (view) currentView = view;
    if (siteList) sites = siteList;
    if (!currentView) return;
    const stamp = ++serial;
    const target = currentView;
    target.innerHTML =
      heading(
        "Activity",
        "Administrative changes and requests to your applications.",
        button("refresh", `${icon("refresh")}Refresh`, "secondary"),
      ) + '<div class="loading">Loading activity…</div>';
    try {
      const [audit, access] = await Promise.all([
        c.api<AuditPage>(`/audit?${buildQuery(auditFilters)}`),
        c.api<AccessPage>(`/access-logs?${buildQuery(accessFilters)}`),
      ]);
      if (stamp !== serial || !target.isConnected) return;
      auditRows = audit.rows;
      auditCursor = audit.next_cursor;
      accessRows = access.rows;
      accessCursor = access.next_cursor;
      target.innerHTML =
        heading(
          "Activity",
          "Administrative changes and requests to your applications, filtered by the investigation view.",
          button("refresh", `${icon("refresh")}Refresh`, "secondary"),
        ) +
        `<section class="section"><div class="section-heading"><h2>Administrative audit</h2><span class="muted">Filters</span></div>${filterForm("audit-filters", auditFilters)}</section>` +
        auditMarkup() +
        `<section class="section"><div class="section-heading"><h2>Application requests</h2><span class="muted">Filters</span></div>${filterForm("access-filters", accessFilters)}</section>` +
        accessMarkup();
      wire();
    } catch (error) {
      await c.handleError(error);
    }
  }
  return { render };
}
