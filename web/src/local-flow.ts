import { esc } from "./ui";
import type { Site } from "./types";
type FlowEvent = { site_id: number; blocked: boolean; response_source: string };
export function mountLocalFlow(
  container: HTMLElement,
  sites: Site[],
  filter: (id: string) => void,
) {
  const upstream = (raw: string) => {
    try {
      const u = new URL(raw);
      return u.protocol + "//" + u.host + u.pathname;
    } catch {
      return "Unavailable";
    }
  };
  const link = (site: Site) => {
    const host = site.hostnames.find((h) => !h.includes("*"));
    return host
      ? `<a href="${esc((site.certificate_id ? "https://" : "http://") + host)}" target="_blank" rel="noreferrer" aria-label="${esc("Open " + site.name)}">Open application ↗</a>`
      : "<small>Wildcard hostname · choose a specific domain to open</small>";
  };
  container.innerHTML = `<details open class="local-flow-panel"><summary>Local traffic flow</summary><p class="muted">Configured routes from Aegis to proxy hosts and upstreams. Select a host to filter the map and log. Counts reflect the live feed sample (up to 200 requests in the last minute), not connection health.</p><div class="local-flow-layout"><div class="local-flow-hub"><strong>Aegis WAF</strong><small>Gateway and protection</small><span data-flow-total></span><button type="button" class="secondary compact" data-flow-all>All applications</button></div><div class="local-flow-branches">${sites.map((site) => `<div class="local-flow-row" data-flow-site="${site.id}"><div class="local-flow-host"><button type="button" class="secondary" data-flow-filter="${site.id}">${esc(site.name)}</button><small>${esc(site.hostnames.join(", "))}</small><small>${site.enabled ? "Enabled route" : "Disabled route"}</small><span data-flow-counts></span>${link(site)}</div><div class="local-flow-link" aria-hidden="true">→</div><div class="local-flow-upstream"><strong>Upstream</strong><code>${esc(upstream(site.upstream))}</code><small data-flow-upstream-count></small></div></div>`).join("") || "<p>No proxy hosts configured.</p>"}</div></div></details>`;
  container.querySelector<HTMLButtonElement>("[data-flow-all]")!.onclick = () =>
    filter("");
  container
    .querySelectorAll<HTMLButtonElement>("[data-flow-filter]")
    .forEach((button) => {
      button.onclick = () => filter(button.dataset.flowFilter!);
    });
  return (events: FlowEvent[], selected: string) => {
    const totals = new Map<
      number,
      { allowed: number; blocked: number; upstream: number }
    >();
    for (const event of events) {
      const value = totals.get(event.site_id) || {
        allowed: 0,
        blocked: 0,
        upstream: 0,
      };
      if (event.blocked) value.blocked++;
      else value.allowed++;
      if (event.response_source === "upstream") value.upstream++;
      totals.set(event.site_id, value);
    }
    container.querySelector<HTMLElement>("[data-flow-total]")!.textContent =
      events.length + " sampled requests";
    container
      .querySelectorAll<HTMLElement>("[data-flow-site]")
      .forEach((row) => {
        const id = Number(row.dataset.flowSite);
        row.hidden = !!selected && String(id) !== selected;
        const value = totals.get(id) || { allowed: 0, blocked: 0, upstream: 0 };
        row.querySelector<HTMLElement>("[data-flow-counts]")!.textContent =
          value.allowed + " allowed · " + value.blocked + " blocked";
        row.querySelector<HTMLElement>(
          "[data-flow-upstream-count]",
        )!.textContent = value.upstream + " recorded upstream responses";
        row
          .querySelector<HTMLButtonElement>("[data-flow-filter]")!
          .setAttribute("aria-pressed", String(String(id) === selected));
      });
  };
}
