import {
  botChallengeMarkup,
  readBotChallenge,
  type BotChallenge,
} from "./bot-challenge";
import { hideLocalTraffic, saveHideLocalTraffic } from "./map-preferences";
import { localLocationNote } from "./location";
import {
  clientAddress,
  responseStatusPanel,
  type ResponseStatus,
} from "./response-status";
import type {
  AddressSelection,
  AddressObject,
  AddressGroup,
} from "./address-objects";
import {
  regionPanels,
  geoSyncStatus,
  makeGeoSyncForm,
  type GeoSource,
  type RegionReport,
} from "./geo-dashboard";
import {
  managedSignatureSummary,
  type ManagedSignatureResult,
} from "./signature-sets";
import { policySummary, type PolicySummary } from "./policy-page";
import { protectionOptions, readProtectionOptions } from "./protection-options";
import { world } from "./world";
type Site = { id: number; name: string; policies?: PolicySummary[] };
export type Protection = {
  bot_challenge?: BotChallenge;
  trusted_addresses?: AddressSelection;
  flood_exempt_addresses?: AddressSelection;
  bot_exempt_addresses?: AddressSelection;
  mode: string;
  requests_per_second: number;
  burst: number;
  site_requests_per_second: number;
  site_burst: number;
  bot_mode: string;
  block_empty_user_agent: boolean;
  trusted_proxies: string[];
  client_ip_header?: string;
  flood_exempt_cidrs?: string[];
  bot_exempt_cidrs?: string[];
};
type Report = {
  geo_sources?: GeoSource[];
  systems?: {
    id: string;
    cpu_percent: number | null;
    cpu_cores: number;
    memory_bytes: number | null;
    memory_limit_bytes: number | null;
    source: string;
  }[];
  dropped_logs: number;
  at: string;
  minutes: number;
  site_id: number;
  connections: number;
  inflight: number;
  reporting_replicas: number;
  geo_updated_at: string | null;
  totals: {
    requests: number;
    blocked: number;
    flagged: number;
    exempt: number;
    errors: number;
    rps: number;
    clients: number;
    mean_duration_ms: number;
  };
  series: { at: string; requests: number; blocked: number }[];
  countries: { country: string; requests: number; blocked: number }[];
  statuses: { status: number; requests: number }[];
  response_statuses: ResponseStatus[];
  signals: { signal: string; requests: number }[];
  recent: {
    id: number;
    at: string;
    site_id: number;
    method: string;
    status: number;
    peer: string;
    client_objects?: string[];
    location_source?: string;
    location_reference_ip?: string;
    country: string;
    blocked: boolean;
    signals: string[];
    managed_signatures?: ManagedSignatureResult;
    policy_name?: string;
    policy_revision?: number;
    protection_exemptions?: string[];
  }[];
};
type Deps = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  esc: (v: unknown) => string;
  heading: (title: string, text: string, buttons?: string) => string;
  table: (headers: string[], rows: string[][], label: string) => string;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (f: FormData) => Promise<void>) => void;
  notice: (message: string, error?: boolean) => void;
  handleError: (error: unknown) => Promise<void>;
};
export const defaultProtection: Protection = {
  mode: "off",
  requests_per_second: 20,
  burst: 60,
  site_requests_per_second: 1000,
  site_burst: 2000,
  bot_mode: "off",
  block_empty_user_agent: false,
  trusted_proxies: [],
  client_ip_header: "x-forwarded-for",
  flood_exempt_cidrs: [],
  bot_exempt_cidrs: [],
};
const signalNames: Record<string, string> = {
  client_rate: "Client request rate",
  application_rate: "Application request rate",
  automation_user_agent: "Automation user agent",
  empty_user_agent: "Missing user agent",
  bot_challenge_required: "Bot verification required",
  bot_challenge_passed: "Bot verification passed",
  bot_challenge_failed: "Bot verification failed",
  bot_would_challenge: "Bot verification recommended (Observe)",
};
const format = (n: number) =>
  new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(n);
const countryName = (code: string) => {
  if (!code) return "Unknown / private network";
  try {
    return (
      new Intl.DisplayNames(undefined, { type: "region" }).of(code) || code
    );
  } catch {
    return code;
  }
};
export function makeDashboardUI(d: Deps) {
  const { api, esc, heading, table } = d;
  let selectedCountry = "",
    selectedRegion = "";
  let hideLocal = hideLocalTraffic();
  const geoSyncForm = makeGeoSyncForm(d);
  let site = "",
    minutes = "15",
    serial = 0,
    sites: Site[] = [];
  async function mount(view: HTMLElement, apps: Site[]) {
    hideLocal = hideLocalTraffic();
    sites = apps;
    if (site && !sites.some((s) => String(s.id) === site)) site = "";
    view.innerHTML =
      heading(
        "Dashboard",
        "A live view of your applications and the traffic reaching them.",
        '<button class="primary" data-action="live-map">Live traffic map</button><button class="secondary" data-action="protection">Protection settings</button>',
      ) +
      `<div class="dashboard-controls"><label>Application<select id="dashboard-site" aria-label="Application"><option value="">All applications</option>${sites.map((s) => `<option value="${s.id}" ${site === String(s.id) ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></label><label>Time range<select id="dashboard-range" aria-label="Time range">${[5, 15, 60].map((n) => `<option value="${n}" ${minutes === String(n) ? "selected" : ""}>Last ${n} minutes</option>`).join("")}</select></label><label class="check"><input type="checkbox" id="dashboard-hide-local" ${hideLocal ? "checked" : ""}><span>Hide local traffic on maps</span></label><span id="dashboard-freshness" class="muted" role="status">Loading traffic…</span></div><div id="dashboard-data" aria-busy="true"></div>`;
    view
      .querySelector<HTMLSelectElement>("#dashboard-site")!
      .addEventListener("change", (e) => {
        site = (e.target as HTMLSelectElement).value;
        void update().catch(d.handleError);
      });
    view
      .querySelector<HTMLSelectElement>("#dashboard-range")!
      .addEventListener("change", (e) => {
        minutes = (e.target as HTMLSelectElement).value;
        void update().catch(d.handleError);
      });
    view.querySelector<HTMLInputElement>("#dashboard-hide-local")!.onchange = (
      event,
    ) => {
      hideLocal = (event.target as HTMLInputElement).checked;
      saveHideLocalTraffic(hideLocal);
      void update().catch(d.handleError);
    };
    await update();
  }
  async function update() {
    const target = document.getElementById("dashboard-data");
    if (!target) return;
    const stamp = ++serial;
    const scope = site;
    try {
      const country = selectedCountry,
        region = selectedRegion;
      const query = `minutes=${minutes}${scope ? `&site_id=${scope}` : ""}`;
      const [r, regional] = await Promise.all([
        api<Report>(
          `/dashboard?${query}${hideLocal ? "&map_exclude_local=true" : ""}`,
        ),
        country
          ? api<RegionReport>(
              `/dashboard/regions?${query}&country=${country}${hideLocal ? "&exclude_local=true" : ""}${region ? `&region=${encodeURIComponent(region)}` : ""}`,
            )
          : Promise.resolve(null),
      ]);
      const regions = regional
        ? regionPanels(regional, countryName(country), esc)
        : null;
      if (stamp !== serial || !target.isConnected) return;
      const resourcesOpen =
        target.querySelector<HTMLDetailsElement>("[data-replica-resources]")
          ?.open || false;
      const t = r.totals;
      const systems = r.systems || [];
      const cpus = systems.filter(
        (s) =>
          typeof s.cpu_percent === "number" &&
          Number.isFinite(s.cpu_percent) &&
          s.cpu_cores > 0,
      );
      const cpuCores = cpus.reduce((n, s) => n + s.cpu_cores, 0);
      const cpu = cpuCores
        ? cpus.reduce((n, s) => n + (s.cpu_percent || 0) * s.cpu_cores, 0) /
          cpuCores
        : null;
      const memory = systems
        .filter((s) => typeof s.memory_bytes === "number")
        .reduce((n, s) => n + (s.memory_bytes || 0), 0);
      const bytes = (n: number) =>
        n >= 1073741824
          ? `${format(n / 1073741824)} GiB`
          : `${format(n / 1048576)} MiB`;
      const resources = `<section class="dashboard-panel"><div class="section-heading"><h2>System performance</h2><span class="muted">All gateway replicas · independent of traffic filters</span></div><div class="resource-metrics"><div><small>CPU usage</small><strong>${cpu === null ? "Unavailable" : `${format(cpu)}%`}</strong></div><div><small>RAM usage</small><strong>${systems.some((s) => typeof s.memory_bytes === "number") ? bytes(memory) : "Unavailable"}</strong></div></div><details class="advanced" data-replica-resources ${resourcesOpen ? "open" : ""}><summary>Per-replica resources</summary>${table(
        ["Replica", "CPU", "RAM", "Memory limit"],
        systems.map((s) => [
          esc(s.id),
          typeof s.cpu_percent !== "number"
            ? "Unavailable"
            : `${format(s.cpu_percent)}%`,
          typeof s.memory_bytes !== "number"
            ? "Unavailable"
            : bytes(s.memory_bytes),
          s.memory_limit_bytes ? bytes(s.memory_limit_bytes) : "Not configured",
        ]),
        "Replica resources",
      )}</details><small>Container usage where available, process fallback otherwise. CPU is normalized to the available CPU quota. PostgreSQL and other host services are excluded.</small></section>`;

      const metric = (title: string, value: string, note: string) =>
        `<article class="metric-card"><span>${title}</span><strong>${value}</strong><small>${note}</small></article>`;
      const geo = new Map(r.countries.map((c) => [c.country, c]));
      const largest = Math.max(1, ...r.countries.map((c) => c.requests));
      const map = world
        .filter((c) => c.code !== "AQ")
        .map((c) => {
          const value = geo.get(c.code);
          const level = value
            ? Math.min(
                4,
                1 +
                  Math.floor(
                    (3 * Math.log1p(value.requests)) / Math.log1p(largest),
                  ),
              )
            : 0;
          return `<path d="${c.path}" class="map-level-${level}" ${/^[A-Z]{2}$/.test(c.code) ? `tabindex="0" role="button" data-map-country="${c.code}" aria-label="View regions in ${esc(c.name)}"` : ""}><title>${esc(c.name)}: ${format(value?.requests || 0)} requests · ${format(value?.blocked || 0)} blocked</title></path>`;
        })
        .join("");
      const now = Date.parse(r.at);
      const start = Math.floor((now - r.minutes * 60000) / 10000) * 10000;
      const end = Math.floor(now / 10000) * 10000;
      const bins = new Map(
        r.series.map((b) => [Math.floor(Date.parse(b.at) / 10000) * 10000, b]),
      );
      const points: { at: number; requests: number; blocked: number }[] = [];
      for (let at = start; at <= end; at += 10000)
        points.push({
          at,
          requests: bins.get(at)?.requests || 0,
          blocked: bins.get(at)?.blocked || 0,
        });
      const peak = Math.max(1, ...points.map((p) => p.requests / 10));
      const path = (key: "requests" | "blocked") =>
        points
          .map(
            (p, i) =>
              `${i ? "L" : "M"}${((i / (points.length - 1)) * 700).toFixed(2)},${(130 - (p[key] / 10 / peak) * 120).toFixed(2)}`,
          )
          .join(" ");
      const rateChart = `<svg class="traffic-chart" viewBox="0 0 700 145" role="img" aria-label="Completed requests and blocks per second over the selected time range"><path class="chart-baseline" d="M0 130H700 M0 70H700 M0 10H700"/><path class="chart-requests" d="${path("requests")}"/><path class="chart-blocks" d="${path("blocked")}"/></svg><div class="chart-labels"><span>${esc(new Date(start).toLocaleTimeString())}</span><span>Peak ${format(peak)} req/s · 10-second buckets</span><span>Now</span></div>`;
      const topCountries = r.countries.slice(0, 8);
      const rowList = (rows: string[], empty: string) =>
        rows.length ? rows.join("") : `<p class="muted">${empty}</p>`;
      const protection = await api<{ site_id: number; settings: Protection }[]>(
        "/protection-settings",
      );
      if (stamp !== serial || !target.isConnected) return;
      const scoped = scope
        ? sites.filter((s) => String(s.id) === scope)
        : sites;
      const focused = document.activeElement as HTMLElement | null;
      const focusKeys = [
        "data-map-country",
        "data-map-region",
        "data-map-back",
        "data-map-clear-region",
        "data-action",
      ];
      const focusKey =
        focused && target.contains(focused)
          ? focusKeys.find((key) => focused.hasAttribute(key))
          : undefined;
      const focusValue = focusKey ? focused!.getAttribute(focusKey) : null;
      const focusID = focused?.dataset.id;
      const statusScroll =
        target.querySelector(".response-status-table")?.scrollTop || 0;
      target.innerHTML = `${r.dropped_logs ? `<div class="notice error">Reporting replicas have dropped ${format(r.dropped_logs)} access logs since starting. Request statistics may be incomplete.</div>` : ""}<div class="metric-grid">${metric("Requests / second", format(t.rps), "Completed requests · trailing 10s")}${metric("Open connections", format(r.connections), `${r.reporting_replicas} reporting replica${r.reporting_replicas === 1 ? "" : "s"} · includes keep-alive`)}${metric("In-flight requests", format(r.inflight), "Currently being processed")}${metric("Total requests", format(t.requests), `Last ${r.minutes} minutes · ${format(t.clients)} clients`)}${metric("Blocked requests", format(t.blocked), `${t.requests ? format((t.blocked / t.requests) * 100) : "0"}% of traffic`)}${metric("Flagged requests", format(t.flagged), `Bot or flood signals · ${format(t.exempt || 0)} requests exempt`)}</div>
   ${resources}<section class="dashboard-panel"><div class="section-heading"><h2>Traffic over time</h2><a class="text-button" href="#live-map">Open live traffic map</a><div class="chart-legend"><span>● Requests</span><span>● Blocked</span></div></div>${rateChart}${!t.requests ? '<p class="dashboard-empty">No traffic in this time range. Connect a proxy host to start seeing requests.</p>' : ""}</section>
   <div class="dashboard-columns"><section class="dashboard-panel world-panel">${regions ? regions.mapPanel : `<div class="section-heading"><h2>Incoming traffic</h2><small>Select a country for regional detail</small></div><svg class="world-map" viewBox="0 5 360 160" role="group" aria-label="World map of incoming requests by country">${map}</svg>`}<div class="map-caption"><span>Lower <span class="map-scale" aria-hidden="true">▁▃▅▇</span> Higher</span><small>${hideLocal ? "Local traffic hidden · " : ""}Country estimates, not precise visitor locations</small></div><div class="geo-status">${r.geo_updated_at ? `Country database updated ${esc(new Date(r.geo_updated_at).toLocaleDateString())}.` : "Enable the country database to locate public client IPs."} <button class="text-button" data-action="geo-update">${r.geo_updated_at ? "Update database" : "Enable map locations"}</button></div>${geoSyncStatus(r.geo_sources || [], esc)}<button class="text-button" data-action="geo-sync">Database sync & regions</button><small>IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a> · Map boundaries: Natural Earth</small></section>
   <section class="dashboard-panel"><h2>${regions ? "Regional traffic" : "Traffic origins"}</h2>${
     regions
       ? regions.counts
       : rowList(
           topCountries.map(
             (c) =>
               `<div class="dashboard-row"><span>${esc(countryName(c.country))}</span><strong>${format(c.requests)}</strong><small>${format(c.blocked)} blocked</small></div>`,
           ),
           "No incoming requests yet.",
         )
   }<p class="muted">Private IPs and unresolved locations are counted as unknown.</p></section></div>${regions?.recent || ""}
   ${responseStatusPanel(r.response_statuses || [], t.requests, scope ? sites.find((s) => String(s.id) === scope)?.name || "Selected proxy host" : "All proxy hosts")}
   <section class="dashboard-panel"><h2>Bot & flood signals</h2>${rowList(
     r.signals.map(
       (s) =>
         `<div class="dashboard-row"><span>${esc(signalNames[s.signal] || s.signal)}</span><strong>${format(s.requests)}</strong></div>`,
     ),
     "No bot or flood signals in this time range.",
   )}<p class="muted">Signals indicate suspicious requests. User-agent signals can be spoofed and do not prove a visitor is a bot.</p></section>
   <section class="dashboard-panel"><div class="section-heading"><h2>Application protection</h2><button class="text-button" data-action="protection">Configure protection</button></div>${rowList(
     scoped.map((s) => {
       const p =
         protection.find((p) => p.site_id === s.id)?.settings ||
         defaultProtection;
       return s.policies?.length
         ? `<div class="dashboard-row"><strong>${esc(s.name)}</strong><span>Policies: ${s.policies.map((p) => esc(p.name)).join(", ")}</span><a href="#policies">Manage</a></div>`
         : `<div class="dashboard-row"><strong>${esc(s.name)}</strong><span>HTTP flood: ${esc(p.mode)}</span><span>Bot signals: ${esc(p.bot_mode)}</span></div>`;
     }),
     "Add a proxy host to configure application protection.",
   )}<p class="muted">Local-mode budgets apply per replica; Redis/Dragonfly shares budgets. Settings reach replicas within the configuration refresh interval.</p></section>
   <section class="dashboard-panel"><div class="section-heading"><h2>Recent requests</h2><span class="muted">Latest 20 in this scope</span></div>${
     r.recent.length
       ? table(
           ["Time", "Application", "Client", "Status", "Outcome", ""],
           r.recent.map((event) => [
             esc(new Date(event.at).toLocaleTimeString()),
             esc(
               sites.find((s) => s.id === event.site_id)?.name ||
                 `Application ${event.site_id}`,
             ),
             clientAddress(event.peer, event.client_objects) +
               (localLocationNote(event)
                 ? `<small>${esc(localLocationNote(event))}</small>`
                 : "") +
               (event.policy_name
                 ? `<small>${esc(event.policy_name)} · v${event.policy_revision}</small>`
                 : "") +
               managedSignatureSummary(event.managed_signatures, esc),
             String(event.status),
             (event.blocked
               ? '<span class="badge danger">Blocked</span>'
               : event.signals.length
                 ? '<span class="badge warning">Flagged · allowed</span>'
                 : '<span class="badge success">Allowed</span>') +
               (event.protection_exemptions?.length
                 ? `<small>${event.protection_exemptions.map((v) => esc(v === "http_flood" ? "HTTP flood exempt" : v === "anti_bot" ? "Anti-bot exempt" : v)).join(" · ")}</small>`
                 : ""),
             `<button type="button" class="secondary compact" data-action="request-details" data-id="${event.id}">View details</button>`,
           ]),
           "Recent requests",
         )
       : '<p class="muted">Requests will appear here as traffic arrives.</p>'
   }</section><p class="page-note">Open connections count gateway sockets. A socket serving several applications appears in each application view; application counts cannot be summed. Requests refresh every 4 seconds with a short logging delay.</p>`;
      const mapAction = (event: Event) => {
        if (
          event.type === "keydown" &&
          !["Enter", " "].includes((event as KeyboardEvent).key)
        )
          return;
        const element = (event.target as Element).closest<HTMLElement>(
          "[data-map-country],[data-map-region],[data-map-back],[data-map-clear-region]",
        );
        if (!element) return;
        event.preventDefault();
        if (element.hasAttribute("data-map-back")) {
          selectedCountry = "";
          selectedRegion = "";
        } else if (element.hasAttribute("data-map-clear-region")) {
          selectedRegion = "";
        } else if (element.dataset.mapCountry) {
          selectedCountry = element.dataset.mapCountry;
          selectedRegion = "";
        } else if (element.dataset.mapRegion) {
          selectedRegion = element.dataset.mapRegion;
        }
        void update().catch(d.handleError);
      };
      const statusTable = target.querySelector(".response-status-table");
      if (statusTable) statusTable.scrollTop = statusScroll;
      if (focusKey) {
        const selector = `[${focusKey}="${CSS.escape(focusValue || "")}"]${focusID ? `[data-id="${CSS.escape(focusID)}"]` : ""}`;
        (
          target.querySelector<HTMLElement>(selector) ||
          target.querySelector<HTMLElement>("#region-title")
        )?.focus();
      }
      target.onclick = mapAction;
      target.onkeydown = mapAction;
      target.removeAttribute("aria-busy");
      const freshness = document.getElementById("dashboard-freshness");
      if (freshness)
        freshness.textContent = `Updated ${new Date(r.at).toLocaleTimeString()} · ${r.reporting_replicas ? "Live" : "Waiting for replica telemetry"}`;
    } catch (e) {
      if (stamp === serial && target.isConnected) {
        const freshness = document.getElementById("dashboard-freshness");
        if (freshness)
          freshness.textContent = "Update failed · showing last received data";
        target.removeAttribute("aria-busy");
      }
      throw e;
    }
  }
  async function protectionForm() {
    if (!sites.length) {
      d.notice("Add a proxy host before configuring protection.", true);
      return;
    }
    const [objects, groups] = await Promise.all([
      api<AddressObject[]>("/address-objects"),
      api<AddressGroup[]>("/address-groups"),
    ]);
    const settings = await api<{ site_id: number; settings: Protection }[]>(
      "/protection-settings",
    );
    d.openEditor(
      "Application protection",
      `<form id="protection-form"><label class="field">Application<select name="site_id" aria-label="Application">${sites.map((s) => `<option value="${s.id}" ${site === String(s.id) ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></label><div id="protection-fields"></div><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Save protection">Save protection</button></div></form>`,
    );
    const form = document.getElementById("protection-form") as HTMLFormElement;
    const select = form.elements.namedItem("site_id") as HTMLSelectElement;
    const mode = (key: string, label: string, value: string) =>
      `<label class="field">${label}<select name="${key}" aria-label="${label}">${["off", "observe", "block"].map((m) => `<option value="${m}" ${value === m ? "selected" : ""}>${m === "off" ? "Off" : m === "observe" ? "Observe · log and allow" : "Block · reject matching requests"}</option>`).join("")}</select></label>`;
    const number = (key: string, label: string, value: number, max: number) =>
      `<label class="field">${label}<input name="${key}" type="number" min="1" max="${max}" value="${value}" required></label>`;
    const fill = () => {
      const p =
        settings.find((s) => String(s.site_id) === select.value)?.settings ||
        defaultProtection;
      const assigned =
        sites.find((site) => String(site.id) === select.value)?.policies || [];
      document.getElementById("protection-fields")!.innerHTML =
        `${policySummary(assigned, esc)}<div ${assigned.length ? "hidden" : ""}><h3>HTTP flood protection</h3>${mode("mode", "Flood mode", p.mode)}<div class="form-grid">${number("requests_per_second", "Requests / second per client", p.requests_per_second, 100000)}${number("burst", "Client burst allowance", p.burst, 1000000)}${number("site_requests_per_second", "Requests / second per application", p.site_requests_per_second, 1000000)}${number("site_burst", "Application burst allowance", p.site_burst, 2000000)}</div><p class="muted">Token buckets permit short bursts, then block with HTTP 429 and Retry-After. Local-mode budgets increase with replica count. System can select Redis/Dragonfly for shared budgets.</p><h3>Bot signals</h3>${mode("bot_mode", "Bot mode", p.bot_mode)}<label class="check"><input name="block_empty_user_agent" type="checkbox" ${p.block_empty_user_agent ? "checked" : ""}><span>Flag requests without a User-Agent header</span></label><p class="muted">Detects declared scanner and headless-browser user agents. Observe first: APIs, monitoring tools and test browsers can be legitimate. Enable selective verification to challenge only requests that reach the configured suspicion threshold.</p>${botChallengeMarkup(p.bot_challenge)}</div>${protectionOptions(p, { objects, groups })}`;
    };
    fill();
    select.addEventListener("change", fill);
    d.formHandler("protection-form", async (f) => {
      const p: Protection = {
        mode: String(f.get("mode")),
        requests_per_second: Number(f.get("requests_per_second")),
        burst: Number(f.get("burst")),
        site_requests_per_second: Number(f.get("site_requests_per_second")),
        site_burst: Number(f.get("site_burst")),
        bot_mode: String(f.get("bot_mode")),
        bot_challenge: readBotChallenge(f),
        block_empty_user_agent: f.has("block_empty_user_agent"),
        ...readProtectionOptions(f),
      };
      await api(`/protection-settings/${f.get("site_id")}`, "PUT", p);
      d.closeEditor();
      await update();
      d.notice(
        "Protection saved. Changes propagate to all replicas automatically.",
      );
    });
  }
  function geoForm() {
    d.openEditor(
      "Enable country locations",
      `<form id="geo-form"><p>Download the current DB-IP Lite country database. It is stored in PostgreSQL and cached by every replica. Visitor IPs stay on your server.</p><p>Location is approximate. Private networks and missing records remain unknown.</p><label class="check"><input type="checkbox" name="accept" required><span>I accept the <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0 license</a> and DB-IP attribution.</span></label><div class="form-actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" class="primary" data-label="Download country database">Download country database</button></div></form>`,
    );
    d.formHandler("geo-form", async (f) => {
      await api("/geolocation/update", "POST", {
        accept_license: f.has("accept"),
      });
      d.closeEditor();
      await update();
      d.notice(
        "Country database updated. New requests will include country estimates.",
      );
    });
  }
  return { mount, update, protectionForm, geoForm, geoSyncForm };
}
