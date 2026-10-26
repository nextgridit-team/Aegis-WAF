import { esc, icon } from "./ui";
import type { Site } from "./types";

type FlowEvent = { site_id: number; blocked: boolean };
type Counts = { allowed: number; blocked: number };
let instance = 0;

export function mountLocalFlow(
  container: HTMLElement,
  sites: Site[],
  filter: (id: string) => void,
) {
  const prefix = `local-flow-${++instance}`;
  const ordered = [...sites].sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { numeric: true }),
  );
  let pageSize = 12;
  let page = 0,
    query = "",
    selected = "",
    disposed = false;
  let totals = new Map<number, Counts>();
  let geometry = "";
  const paths = new Map<number, string>();
  const effects = new Set<ReturnType<typeof setTimeout>>();
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  const number = new Intl.NumberFormat();
  container.innerHTML = `<details open class="local-flow-panel"><summary>Local traffic flow <span class="local-flow-host-total">${sites.length} proxy ${sites.length === 1 ? "host" : "hosts"}</span></summary><div class="local-flow-toolbar"><div class="local-flow-legend"><span><i class="local-flow-key local-flow-allowed" aria-hidden="true">✓</i> Allowed</span><span><i class="local-flow-key local-flow-blocked" aria-hidden="true">⊘</i> Blocked</span><span class="local-flow-sample" data-flow-total>Waiting for traffic</span></div><label class="local-flow-search">${icon("globe")}<input type="search" aria-label="Find a proxy host" placeholder="Find a host or domain" autocomplete="off"></label></div><div class="local-flow-layout"><svg class="local-flow-overlay" aria-hidden="true"><g data-flow-lines></g><g data-flow-packets></g></svg><div class="local-flow-hub"><button type="button" data-flow-all aria-label="All applications" aria-pressed="true"><span class="local-flow-shield">${icon("shield")}</span><span><strong>Aegis WAF</strong><small>All applications</small></span></button></div><div class="local-flow-branches" aria-label="Proxy hosts"></div></div><div class="local-flow-pagination" hidden><span data-flow-range role="status"></span><div><button type="button" class="secondary compact" data-flow-prev aria-label="Previous hosts">Previous</button><button type="button" class="secondary compact" data-flow-next aria-label="Next hosts">Next</button></div></div><p class="local-flow-caption"><span data-flow-scope>Select a host to filter the map and log.</span> Last-minute request sample, not a health check.</p></details>`;
  const details = container.querySelector<HTMLDetailsElement>("details")!;
  const layout = container.querySelector<HTMLElement>(".local-flow-layout")!;
  const hub = container.querySelector<HTMLElement>(".local-flow-hub")!;
  const branches = container.querySelector<HTMLElement>(
    ".local-flow-branches",
  )!;
  const search = container.querySelector<HTMLInputElement>("input")!;
  const all = container.querySelector<HTMLButtonElement>("[data-flow-all]")!;
  const previous =
    container.querySelector<HTMLButtonElement>("[data-flow-prev]")!;
  const next = container.querySelector<HTMLButtonElement>("[data-flow-next]")!;
  const pagination = container.querySelector<HTMLElement>(
    ".local-flow-pagination",
  )!;
  const svg = container.querySelector<SVGSVGElement>(".local-flow-overlay")!;
  const lines = svg.querySelector<SVGGElement>("[data-flow-lines]")!;
  const packets = svg.querySelector<SVGGElement>("[data-flow-packets]")!;
  function clear() {
    effects.forEach(clearTimeout);
    effects.clear();
    packets.replaceChildren();
  }
  function matching() {
    return ordered.filter(
      (site) =>
        !query ||
        `${site.name} ${site.hostnames.join(" ")}`
          .toLocaleLowerCase()
          .includes(query),
    );
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
    const vertical = layout.clientWidth <= 680;
    const scale = area.width / layout.clientWidth;
    paths.clear();
    const x = vertical
      ? start.left + start.width / 2 - area.left
      : start.right - area.left;
    const y = vertical
      ? start.bottom - area.top
      : start.top + start.height / 2 - area.top;
    branches
      .querySelectorAll<HTMLElement>("[data-flow-site]")
      .forEach((row) => {
        const end = row.getBoundingClientRect();
        const targetX = end.left + end.width / 2 - area.left;
        const targetY = end.top - area.top;
        // Dedicated gutters above every row keep connections out of other pills.
        const railY = targetY - 13 * scale;
        const spine = vertical ? 9 * scale : x + 20 * scale;
        const route = vertical
          ? `M${x},${y} V${y + 12 * scale} H${spine} V${railY} H${targetX} V${targetY}`
          : `M${x},${y} H${spine} V${railY} H${targetX} V${targetY}`;
        paths.set(Number(row.dataset.flowSite), route);
      });
    const key = JSON.stringify([selected, ...paths]);
    if (key === geometry) return;
    geometry = key;
    clear();
    lines.replaceChildren();
    for (const [id, path] of paths) {
      const line = document.createElementNS(svg.namespaceURI, "path");
      line.setAttribute("d", path);
      line.setAttribute(
        "class",
        "local-flow-route" + (String(id) === selected ? " is-selected" : ""),
      );
      lines.append(line);
    }
  }
  function updateCounts() {
    branches
      .querySelectorAll<HTMLElement>("[data-flow-site]")
      .forEach((row) => {
        const id = Number(row.dataset.flowSite),
          outside = !!selected && String(id) !== selected;
        const value = totals.get(id) || { allowed: 0, blocked: 0 };
        row.dataset.selected = String(String(id) === selected);
        row.dataset.outside = String(outside);
        row.dataset.blocked = String(!outside && value.blocked > 0);
        row
          .querySelector<HTMLButtonElement>("[data-flow-filter]")!
          .setAttribute("aria-pressed", String(String(id) === selected));
        for (const kind of ["allowed", "blocked"] as const) {
          const count = row.querySelector<HTMLElement>(`[data-flow-${kind}]`)!;
          count.querySelector("b")!.textContent = outside
            ? "—"
            : number.format(value[kind]);
          count.setAttribute(
            "aria-label",
            outside
              ? "Outside the selected traffic filter"
              : `${value[kind]} ${kind} requests`,
          );
        }
      });
    all.setAttribute("aria-pressed", String(!selected));
    all.querySelector("small")!.textContent = selected
      ? "Show all applications"
      : "All applications";
    const selectedSite = sites.find((site) => String(site.id) === selected);
    const name = selectedSite?.name;
    const domain = selectedSite?.hostnames[0];
    container.querySelector<HTMLElement>("[data-flow-scope]")!.textContent =
      selected
        ? `Filtered to ${name || "selected host"}${domain ? " · " + domain : ""}. Other host counts are outside this filter.`
        : "Select a host to filter the map and log.";
  }
  function renderHosts() {
    const matches = matching();
    page = Math.max(
      0,
      Math.min(page, Math.ceil(matches.length / pageSize) - 1),
    );
    const visible = matches.slice(page * pageSize, (page + 1) * pageSize);
    branches.innerHTML =
      visible
        .map((site) => {
          const host = site.hostnames.find((h) => !h.includes("*"));
          const domain = site.hostnames[0] || "No hostname";
          const info = `${site.hostnames.join(", ") || "No hostnames"}. ${site.enabled ? "Enabled route" : "Disabled route"}.`;
          const link = host
            ? `<a class="local-flow-open" href="${esc((site.certificate_id ? "https://" : "http://") + host)}" target="_blank" rel="noreferrer" aria-label="${esc("Open " + site.name)}" title="${esc("Open " + host)}">↗</a>`
            : `<span class="local-flow-wildcard" title="Choose a specific hostname to open a wildcard route" aria-label="Wildcard hostname">*</span>`;
          return `<div class="local-flow-row" data-flow-site="${site.id}" data-disabled="${!site.enabled}"><button type="button" class="local-flow-host" data-flow-filter="${site.id}" aria-label="${esc(site.name)}" aria-describedby="${prefix}-${site.id}" aria-pressed="false" title="${esc(site.name + "\n" + info)}"><span class="local-flow-name"><strong>${esc(site.name)}</strong><small>${site.enabled ? esc(domain) : '<span class="local-flow-disabled">Disabled</span> ' + esc(domain)}</small></span><span class="local-flow-counts" data-flow-counts><span data-flow-allowed class="local-flow-allowed"><i aria-hidden="true">✓</i><b>0</b></span><span data-flow-blocked class="local-flow-blocked"><i aria-hidden="true">⊘</i><b>0</b></span></span></button>${link}<span class="local-flow-description" id="${prefix}-${site.id}">${esc(info)}</span></div>`;
        })
        .join("") ||
      `<div class="local-flow-empty"><span>${sites.length ? "No hosts match your search." : "Add a proxy host to see its traffic here."}</span>${query ? '<button type="button" class="secondary compact" data-flow-clear>Clear search</button>' : ""}</div>`;
    branches
      .querySelectorAll<HTMLButtonElement>("[data-flow-filter]")
      .forEach((button) => {
        button.onclick = () => filter(button.dataset.flowFilter!);
      });
    branches
      .querySelector<HTMLButtonElement>("[data-flow-clear]")
      ?.addEventListener("click", () => {
        search.value = "";
        query = "";
        page = 0;
        renderHosts();
        search.focus();
      });
    pagination.hidden = matches.length <= pageSize;
    previous.disabled = page === 0;
    next.disabled = (page + 1) * pageSize >= matches.length;
    container.querySelector<HTMLElement>("[data-flow-range]")!.textContent =
      matches.length
        ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, matches.length)} of ${matches.length} hosts`
        : "No matching hosts";
    // Announce search results even when pagination is unnecessary.
    search.setAttribute(
      "aria-description",
      `${matches.length} matching hosts. Search changes this diagram only.`,
    );
    updateCounts();
    draw();
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
    dot.setAttribute("r", "3");
    dot.setAttribute("cy", event.blocked ? "3" : "-3");
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
  all.onclick = () => filter("");
  search.oninput = () => {
    query = search.value.trim().toLocaleLowerCase();
    page = 0;
    renderHosts();
  };
  search.onkeydown = (event) => {
    if (event.key === "Escape" && search.value) {
      event.preventDefault();
      search.value = "";
      query = "";
      page = 0;
      renderHosts();
    }
  };
  previous.onclick = () => {
    page--;
    renderHosts();
  };
  next.onclick = () => {
    page++;
    renderHosts();
  };
  const resized = new ResizeObserver(() => {
    if (disposed) return;
    const size = layout.clientWidth <= 680 ? 6 : 12;
    if (pageSize !== size) {
      const matches = matching();
      const index = matches.findIndex((site) => String(site.id) === selected);
      const anchor =
        index >= page * pageSize && index < (page + 1) * pageSize
          ? index
          : page * pageSize;
      pageSize = size;
      page = Math.floor(anchor / size);
      renderHosts();
    } else draw();
  });
  resized.observe(layout);
  details.addEventListener("toggle", draw);
  motion.addEventListener("change", clear);
  renderHosts();
  const update = (
    events: FlowEvent[],
    selection: string,
    fresh: FlowEvent[] = [],
  ) => {
    if (disposed) return;
    if (!events.length) clear();
    const changed = selected !== selection;
    selected = selection;
    totals = new Map();
    for (const event of events) {
      const value = totals.get(event.site_id) || { allowed: 0, blocked: 0 };
      if (event.blocked) value.blocked++;
      else value.allowed++;
      totals.set(event.site_id, value);
    }
    container.querySelector<HTMLElement>("[data-flow-total]")!.textContent =
      `${number.format(events.length)} sampled requests`;
    if (changed && selected) {
      const hadQuery = !!query;
      const priorPage = page;
      const focused =
        document.activeElement instanceof HTMLElement
          ? document.activeElement.dataset.flowFilter
          : undefined;
      query = "";
      search.value = "";
      page = Math.max(
        0,
        Math.floor(
          ordered.findIndex((site) => String(site.id) === selected) / pageSize,
        ),
      );
      if (hadQuery || page !== priorPage) {
        renderHosts();
        if (focused === selected)
          branches
            .querySelector<HTMLButtonElement>(
              `[data-flow-filter="${selected}"]`,
            )
            ?.focus();
      } else {
        updateCounts();
        draw();
      }
    } else {
      updateCounts();
      draw();
    }
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
