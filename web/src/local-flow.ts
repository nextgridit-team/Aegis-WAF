import { esc } from "./ui";
import type { Site } from "./types";
type FlowEvent = { site_id: number; blocked: boolean };
export function mountLocalFlow(
  container: HTMLElement,
  sites: Site[],
  filter: (id: string) => void,
) {
  const link = (site: Site) => {
    const host = site.hostnames.find((h) => !h.includes("*"));
    return host
      ? `<a href="${esc((site.certificate_id ? "https://" : "http://") + host)}" target="_blank" rel="noreferrer" aria-label="${esc("Open " + site.name)}">Open application ↗</a>`
      : "<small>Wildcard hostname · choose a specific domain to open</small>";
  };
  container.innerHTML = `<details open class="local-flow-panel"><summary>Local traffic flow</summary><p class="muted">Aegis to proxy hosts. Green pulses passed WAF checks; red pulses were blocked for that host. Select a host to filter the map and log. Counts reflect the live feed sample (up to 200 requests in the last minute), not connection health.</p><div class="local-flow-layout"><svg class="local-flow-overlay" aria-hidden="true"><g data-flow-lines></g><g data-flow-packets></g></svg><div class="local-flow-hub"><strong>Aegis WAF</strong><small>Gateway and protection</small><span data-flow-total></span><button type="button" class="secondary compact" data-flow-all>All applications</button></div><div class="local-flow-branches">${sites.map((site) => `<div class="local-flow-row" data-flow-site="${site.id}"><div class="local-flow-host"><button type="button" class="secondary" data-flow-filter="${site.id}">${esc(site.name)}</button><small>${esc(site.hostnames.join(", "))}</small><small>${site.enabled ? "Enabled route" : "Disabled route"}</small><span data-flow-counts></span>${link(site)}</div></div>`).join("") || "<p>No proxy hosts configured.</p>"}</div></div></details>`;
  const details = container.querySelector<HTMLDetailsElement>("details")!;
  const layout = container.querySelector<HTMLElement>(".local-flow-layout")!;
  const hub = container.querySelector<HTMLElement>(".local-flow-hub")!;
  const svg = container.querySelector<SVGSVGElement>("svg")!;
  const lines = svg.querySelector<SVGGElement>("[data-flow-lines]")!;
  const packets = svg.querySelector<SVGGElement>("[data-flow-packets]")!;
  const paths = new Map<number, string>();
  const effects = new Set<ReturnType<typeof setTimeout>>();
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  let disposed = false;
  let geometry = "";
  function clear() {
    effects.forEach(clearTimeout);
    effects.clear();
    packets.replaceChildren();
  }
  function draw() {
    if (disposed || !details.open || !layout.isConnected) {
      clear();
      return;
    }
    const area = layout.getBoundingClientRect(),
      start = hub.getBoundingClientRect();
    if (!area.width || !area.height) return;
    svg.setAttribute("viewBox", `0 0 ${area.width} ${area.height}`);
    const vertical = matchMedia("(max-width:700px)").matches;
    paths.clear();
    container
      .querySelectorAll<HTMLElement>("[data-flow-site]")
      .forEach((row) => {
        if (row.hidden) return;
        const end = row.getBoundingClientRect();
        const x = vertical
          ? start.left + start.width / 2 - area.left
          : start.right - area.left;
        const y = vertical
          ? start.bottom - area.top
          : start.top + start.height / 2 - area.top;
        const targetX = vertical
          ? end.left + end.width / 2 - area.left
          : end.left - area.left;
        const targetY = vertical
          ? end.top - area.top
          : end.top + end.height / 2 - area.top;
        const middle = vertical ? (y + targetY) / 2 : (x + targetX) / 2;
        paths.set(
          Number(row.dataset.flowSite),
          vertical
            ? `M${x},${y} V${middle} H${targetX} V${targetY}`
            : `M${x},${y} H${middle} V${targetY} H${targetX}`,
        );
      });
    const key = JSON.stringify([...paths]);
    if (key === geometry) return;
    geometry = key;
    clear();
    lines.replaceChildren();
    for (const path of paths.values()) {
      const line = document.createElementNS(svg.namespaceURI, "path");
      line.setAttribute("d", path);
      line.setAttribute("class", "local-flow-route");
      lines.append(line);
    }
  }
  function pulse(event: FlowEvent) {
    if (
      disposed ||
      motion.matches ||
      document.hidden ||
      !details.open ||
      effects.size >= 16
    )
      return;
    const path = paths.get(event.site_id);
    if (!path) return;
    const dot = document.createElementNS(svg.namespaceURI, "circle");
    dot.setAttribute("r", "4");
    dot.setAttribute("cy", event.blocked ? "4" : "-4");
    dot.setAttribute(
      "class",
      "local-flow-packet " + (event.blocked ? "live-blocked" : "live-allowed"),
    );
    dot.setAttribute("data-outcome", event.blocked ? "blocked" : "allowed");
    const move = document.createElementNS(
      svg.namespaceURI,
      "animateMotion",
    ) as SVGAnimateMotionElement;
    move.setAttribute("path", path);
    move.setAttribute("dur", "1.8s");
    move.setAttribute("begin", "indefinite");
    move.setAttribute("fill", "freeze");
    move.setAttribute("calcMode", "paced");
    dot.append(move);
    packets.append(dot);
    move.beginElement();
    const timer = setTimeout(() => {
      dot.remove();
      effects.delete(timer);
    }, 1800);
    effects.add(timer);
  }
  container.querySelector<HTMLButtonElement>("[data-flow-all]")!.onclick = () =>
    filter("");
  container
    .querySelectorAll<HTMLButtonElement>("[data-flow-filter]")
    .forEach((button) => {
      button.onclick = () => filter(button.dataset.flowFilter!);
    });
  const resized = new ResizeObserver(draw);
  resized.observe(layout);
  details.addEventListener("toggle", draw);
  motion.addEventListener("change", clear);
  const update = (
    events: FlowEvent[],
    selected: string,
    fresh: FlowEvent[] = [],
  ) => {
    if (disposed) return;
    if (!events.length) clear();
    const totals = new Map<number, { allowed: number; blocked: number }>();
    for (const event of events) {
      const value = totals.get(event.site_id) || { allowed: 0, blocked: 0 };
      if (event.blocked) value.blocked++;
      else value.allowed++;
      totals.set(event.site_id, value);
    }
    container.querySelector<HTMLElement>("[data-flow-total]")!.textContent =
      events.length + " sampled requests";
    container
      .querySelectorAll<HTMLElement>("[data-flow-site]")
      .forEach((row) => {
        const id = Number(row.dataset.flowSite);
        row.hidden = !!selected && String(id) !== selected;
        const value = totals.get(id) || { allowed: 0, blocked: 0 };
        row.querySelector<HTMLElement>("[data-flow-counts]")!.textContent =
          value.allowed + " allowed · " + value.blocked + " blocked";
        row
          .querySelector<HTMLButtonElement>("[data-flow-filter]")!
          .setAttribute("aria-pressed", String(String(id) === selected));
      });
    draw();
    fresh.slice(-16).forEach(pulse);
  };
  return Object.assign(update, {
    dispose: () => {
      disposed = true;
      clear();
      resized.disconnect();
      details.removeEventListener("toggle", draw);
      motion.removeEventListener("change", clear);
    },
  });
}
