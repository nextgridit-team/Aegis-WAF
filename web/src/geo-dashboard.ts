import { clientAddress } from "./response-status";
import { usStates } from "./us-states";
export type GeoSource = {
  kind: string;
  enabled: boolean;
  auto_sync: boolean;
  status: string;
  error: string;
  updated_at: string | null;
  next_sync: string | null;
};
export type RegionReport = {
  country: string;
  region: string;
  regions: {
    region_code: string;
    region_name: string;
    requests: number;
    blocked: number;
  }[];
  recent: {
    id: number;
    at: string;
    method: string;
    status: number;
    peer: string;
    client_objects?: string[];
    blocked: boolean;
    region_code: string;
    region_name: string;
  }[];
};
type Esc = (v: unknown) => string;
export function geoSyncStatus(sources: GeoSource[], esc: Esc) {
  return sources
    .filter((source) => source.enabled || source.updated_at)
    .map(
      (source) =>
        `<small>${source.kind === "city" ? "Regions" : "Country"}: ${esc(source.status)}${source.auto_sync ? " · monthly sync" : ""}${source.updated_at ? ` · data updated ${esc(new Date(source.updated_at).toLocaleDateString())}` : ""}${source.error ? ` · ${esc(source.error)}` : ""}</small>`,
    )
    .join("");
}
export function regionPanels(
  report: RegionReport,
  countryName: string,
  esc: Esc,
) {
  const rows = report.regions;
  const byCode = new Map<string, { requests: number; blocked: number }>();
  for (const row of rows) {
    const item = byCode.get(row.region_code) || { requests: 0, blocked: 0 };
    item.requests += row.requests;
    item.blocked += row.blocked;
    byCode.set(row.region_code, item);
  }
  const max = Math.max(1, ...rows.map((row) => row.requests));
  const map =
    report.country === "US"
      ? `<svg class="region-map" viewBox="0 0 975 610" role="group" aria-label="United States traffic by state">${usStates
          .map((state) => {
            const count = byCode.get(state.code);
            const level = count
              ? Math.min(
                  4,
                  1 +
                    Math.floor(
                      (3 * Math.log1p(count.requests)) / Math.log1p(max),
                    ),
                )
              : 0;
            return `<path d="${state.path}" class="map-level-${level} ${report.region === state.code ? "map-selected" : ""}" tabindex="0" role="button" data-map-region="${state.code}" aria-label="View ${state.name} requests"><title>${state.name}: ${count?.requests || 0} requests · ${count?.blocked || 0} blocked</title></path>`;
          })
          .join(
            "",
          )}</svg><small>U.S. Census Bureau 2017 boundaries via us-atlas · Alaska and Hawaii insets</small>`
      : '<p class="muted">Regional counts are shown alongside this view. State boundaries are currently available for the United States.</p>';
  const counts =
    rows
      .map(
        (row) =>
          `<div class="dashboard-row"><button type="button" class="text-button" data-map-region="${esc(row.region_code || "unknown")}">${esc(row.region_name || row.region_code || "Unknown region")}</button><strong>${row.requests}</strong><small>${row.blocked} blocked</small></div>`,
      )
      .join("") ||
    '<p class="muted">No regional request records in this scope.</p>';
  const mapPanel = `<div class="section-heading"><h2 id="region-title" tabindex="-1">${esc(countryName)} · regions</h2><button type="button" class="text-button" data-map-back>Back to world</button></div>${map}<p class="muted">IP location is approximate. Older country-only logs and unresolved regions remain unknown. Enable regional data to record state detail on future requests.</p>`;
  const recent = report.region
    ? `<section class="dashboard-panel"><div class="section-heading"><h2>${esc(report.region === "unknown" ? "Unknown region" : usStates.find((state) => report.country === "US" && state.code === report.region)?.name || report.region)} · recent requests</h2><button type="button" class="text-button" data-map-clear-region>All regions</button></div>${report.recent.length ? `<div class="table-wrap" role="region" aria-label="Regional requests"><table><thead><tr><th>Time</th><th>Client</th><th>Request</th><th>Outcome</th><th></th></tr></thead><tbody>${report.recent.map((event) => `<tr><td>${esc(new Date(event.at).toLocaleTimeString())}</td><td>${clientAddress(event.peer, event.client_objects)}</td><td>${esc(event.method)} · ${event.status}</td><td>${event.blocked ? "Blocked" : "Allowed"}</td><td><button type="button" class="secondary compact" data-action="request-details" data-id="${event.id}">View details</button></td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No requests for this region in the selected application/time range.</p>'}</section>`
    : "";
  return { mapPanel, counts, recent };
}
type FormContext = {
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
  openEditor: (title: string, body: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (f: FormData) => Promise<void>) => void;
  notice: (m: string) => void;
};
export function makeGeoSyncForm(c: FormContext) {
  return async () => {
    const status = await c.api<GeoSource[]>("/geolocation/status");
    const detail = status.some(
      (source) => source.kind === "city" && source.enabled,
    )
      ? "city"
      : "country";
    c.openEditor(
      "Location databases and sync",
      `<form id="geo-sync-form"><p>Download free DB-IP Lite data once, then perform local in-memory lookups. Visitor IPs are never sent to DB-IP.</p><label class="field">Location detail<select name="detail" aria-label="Location detail"><option value="country" ${detail === "country" ? "selected" : ""}>Country only · smaller database</option><option value="city" ${detail === "city" ? "selected" : ""}>Country and state/region · City Lite database</option></select></label><p class="muted">Regional data uses a substantially larger database and additional RAM/storage in each replica. It is loaded separately from routing configuration; lookups for logs run after forwarding. City names and coordinates are not written to access logs.</p><label class="check"><input type="checkbox" name="auto_sync" checked><span>Refresh monthly automatically</span></label><label class="check"><input type="checkbox" name="accept" required><span>I accept the <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0 license</a> and DB-IP attribution</span></label><p class="muted">Choosing country-only disables new regional enrichment and future regional syncs. Existing regional logs and the downloaded public database remain stored.</p><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Queue database sync">Queue database sync</button></div></form>`,
    );
    c.formHandler("geo-sync-form", async (f) => {
      await c.api("/geolocation/sync", "POST", {
        detail: f.get("detail"),
        auto_sync: f.has("auto_sync"),
        accept_license: f.has("accept"),
      });
      c.closeEditor();
      c.notice(
        "Database sync queued. Existing data remains active until its replacement is verified.",
      );
    });
  };
}
