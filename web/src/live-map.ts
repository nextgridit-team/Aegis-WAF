import { world } from "./world";
import { esc, heading } from "./ui";
import { clientAddress, responseSource } from "./response-status";
type Event = {
  id: number;
  at: string;
  site_id: number;
  site_name: string | null;
  method: string;
  status: number;
  blocked: boolean;
  peer: string;
  country: string;
  region_name: string;
  client_objects?: string[];
  response_source: string;
};
type C = {
  api: <T>(p: string) => Promise<T>;
  sites: () => { id: number; name: string }[];
  handleError: (e: unknown) => Promise<void>;
};
export function makeLiveMap(c: C) {
  let active = false,
    generation = 0,
    timer: ReturnType<typeof setTimeout> | undefined;
  let dispose = () => {};
  const effects = new Set<ReturnType<typeof setTimeout>>();
  const stop = () => {
    active = false;
    generation++;
    clearTimeout(timer);
    effects.forEach(clearTimeout);
    effects.clear();
    dispose();
    dispose = () => {};
  };
  async function mount(view: HTMLElement) {
    stop();
    active = true;
    let selected = "",
      paused = false,
      first = true;
    const seen = new Set<number>();
    let reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    view.innerHTML =
      heading(
        "Live traffic map",
        "Traffic observed by this gateway. Green passed WAF checks; red was blocked.",
        '<a class="secondary" href="#dashboard">Back to dashboard</a>',
      ) +
      `<div class="live-controls"><label class="field">Application<select aria-label="Live map application"><option value="">All proxy hosts</option>${c
        .sites()
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join(
          "",
        )}</select></label><button type="button" class="secondary" data-live-pause>Pause feed</button><label class="check"><input type="checkbox" data-live-follow ${reduced ? "" : "checked"}><span>Follow new requests</span></label><span data-live-state role="status">Connecting…</span></div><section class="dashboard-panel live-map-panel"><div class="live-map-legend"><span class="live-allowed">● Allowed</span><span class="live-blocked">● Blocked</span><span data-live-counts></span></div><svg class="live-world" viewBox="0 5 360 170" role="img" aria-label="Observed requests by country; destination is a logical gateway marker"><g>${world.map((country) => `<path d="${country.path}" data-live-country="${esc(country.code)}" class="live-country"><title>${esc(country.name)}</title></path>`).join("")}</g><g data-live-effects aria-hidden="true"></g><g class="live-gateway"><circle cx="25" cy="155" r="2"/><text x="30" y="156">Unknown / private</text><circle cx="185" cy="155" r="2.5"/><text x="190" y="156">Aegis · logical target</text></g></svg><p class="muted">Locations are approximate country areas, not individual IP coordinates. The destination marker is a logical gateway, not a geographic location. Unknown/private locations use a separate logical marker and remain in the log. Enable local Geo data from Dashboard to locate public clients.</p><small>IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a> · Map boundaries: Natural Earth</small></section><section class="dashboard-panel"><div class="section-heading"><h2>Live request log</h2><span>Green = allowed · red = blocked</span></div><div class="table-wrap live-log" role="region" aria-label="Live request log" tabindex="0"><table><thead><tr><th scope="col">Time</th><th scope="col">Proxy host</th><th scope="col">Client</th><th scope="col">Location</th><th scope="col">Result</th><th scope="col">HTTP / source</th><th scope="col">Details</th></tr></thead><tbody data-live-rows></tbody></table><p data-live-empty class="muted">Waiting for completed requests…</p></div><p class="muted">Completed requests arrive after asynchronous logging, usually with a 1–2 second delay; long streams appear when they finish. Each refresh reads up to 200 recorded requests from the last minute; this is a best-effort live view. The log retains 200 rows and animations are capped at 30 simultaneous effects. Activity provides the persisted request records.</p></section>`;
    const select = view.querySelector<HTMLSelectElement>("select")!,
      pause = view.querySelector<HTMLButtonElement>("[data-live-pause]")!,
      follow = view.querySelector<HTMLInputElement>("[data-live-follow]")!,
      state = view.querySelector<HTMLElement>("[data-live-state]")!,
      body = view.querySelector<HTMLElement>("[data-live-rows]")!,
      log = view.querySelector<HTMLElement>(".live-log")!,
      layer = view.querySelector<SVGGElement>("[data-live-effects]")!;
    const countryPaths = new Map<string, SVGPathElement>();
    view
      .querySelectorAll<SVGPathElement>("[data-live-country]")
      .forEach((path) => countryPaths.set(path.dataset.liveCountry!, path));
    const countryNames = new Map(
      world.map((country) => [country.code, country.name]),
    );
    function animate(event: Event) {
      if (reduced || effects.size >= 30) return;
      const path = countryPaths.get(event.country);
      const bounds = path?.getBBox();
      const x = bounds && bounds.width ? bounds.x + bounds.width / 2 : 25,
        y = bounds && bounds.height ? bounds.y + bounds.height / 2 : 155;
      const node = document.createElementNS("http://www.w3.org/2000/svg", "g");
      node.setAttribute(
        "class",
        event.blocked ? "live-blocked" : "live-allowed",
      );
      const arc = document.createElementNS(node.namespaceURI, "path");
      arc.setAttribute(
        "d",
        `M${x},${y} Q${(x + 185) / 2},${Math.max(8, Math.min(y, 155) - 28)} 185,155`,
      );
      arc.setAttribute("pathLength", "1");
      arc.setAttribute("class", "live-flow");
      const pulse = document.createElementNS(node.namespaceURI, "circle");
      pulse.setAttribute("cx", String(x));
      pulse.setAttribute("cy", String(y));
      pulse.setAttribute("r", "2");
      pulse.setAttribute("class", "live-pulse");
      node.append(arc, pulse);
      layer.append(node);
      const cleanup = setTimeout(() => {
        node.remove();
        effects.delete(cleanup);
      }, 1800);
      effects.add(cleanup);
    }
    function append(events: Event[]) {
      let removedHeight = 0;
      const oldTop = log.scrollTop;
      body.insertAdjacentHTML(
        "beforeend",
        events
          .map(
            (event) =>
              `<tr class="${event.blocked ? "live-row-blocked" : "live-row-allowed"}"><td>${esc(new Date(event.at).toLocaleTimeString())}</td><td>${esc(event.site_name || "Deleted proxy host #" + event.site_id)}</td><td>${clientAddress(event.peer, event.client_objects)}</td><td>${esc(countryNames.get(event.country) || "Unknown location")}${event.region_name ? `<small>${esc(event.region_name)}</small>` : ""}</td><td><span class="badge ${event.blocked ? "danger" : "success"}">${event.blocked ? "Blocked" : "Allowed"}</span></td><td>${esc(event.method)} · ${event.status}<small>${esc(responseSource(event.response_source))}</small></td><td><button type="button" class="secondary compact" data-action="request-details" data-id="${event.id}">View details</button></td></tr>`,
          )
          .join(""),
      );
      while (body.children.length > 200) {
        removedHeight += (body.firstElementChild as HTMLElement).offsetHeight;
        body.firstElementChild!.remove();
      }
      if (body.children.length)
        view.querySelector<HTMLElement>("[data-live-empty]")!.hidden = true;
      log.scrollTop = follow.checked
        ? log.scrollHeight
        : Math.max(0, oldTop - removedHeight);
    }
    async function poll() {
      if (!active || !view.isConnected || paused) return;
      if (document.hidden) {
        timer = setTimeout(poll, 1000);
        return;
      }
      const stamp = ++generation;
      try {
        const report = await c.api<{ events: Event[] }>(
          "/live-traffic" +
            (selected ? "?site_id=" + encodeURIComponent(selected) : ""),
        );
        if (!active || stamp !== generation || !view.isConnected) return;
        const fresh = report.events.filter((event) => !seen.has(event.id));
        report.events.forEach((event) => seen.add(event.id));
        while (seen.size > 2000) seen.delete(seen.values().next().value!);
        const visible = first ? fresh.slice(-20) : fresh;
        append(visible);
        if (!first) fresh.slice(-30).forEach(animate);
        first = false;
        const blocked = report.events.filter((event) => event.blocked).length;
        view.querySelector<HTMLElement>("[data-live-counts]")!.textContent =
          `Recent window: ${report.events.length - blocked} allowed · ${blocked} blocked`;
        if (state.textContent !== "Live · refreshes every second")
          state.textContent = "Live · refreshes every second";
      } catch (error) {
        if (!active || stamp !== generation) return;
        state.textContent = "Connection interrupted · retrying";
        await c.handleError(error);
      } finally {
        if (active && view.isConnected && !paused && stamp === generation)
          timer = setTimeout(poll, 1000);
      }
    }
    pause.onclick = () => {
      paused = !paused;
      generation++;
      clearTimeout(timer);
      pause.textContent = paused ? "Resume feed" : "Pause feed";
      state.textContent = paused
        ? "Paused · WAF protection continues"
        : "Reconnecting…";
      if (!paused) void poll();
    };
    select.onchange = () => {
      selected = select.value;
      generation++;
      clearTimeout(timer);
      seen.clear();
      body.innerHTML = "";
      first = true;
      view.querySelector<HTMLElement>("[data-live-empty]")!.hidden = false;
      effects.forEach(clearTimeout);
      effects.clear();
      layer.replaceChildren();
      if (!paused) void poll();
    };
    follow.onchange = () => {
      if (follow.checked) log.scrollTop = log.scrollHeight;
    };
    log.addEventListener(
      "wheel",
      (event) => {
        if (event.deltaY < 0) follow.checked = false;
      },
      { passive: true },
    );
    log.addEventListener(
      "touchmove",
      () => {
        follow.checked = false;
      },
      { passive: true },
    );
    log.addEventListener("keydown", (event) => {
      if (["ArrowUp", "PageUp", "Home"].includes(event.key))
        follow.checked = false;
    });
    const preference = matchMedia("(prefers-reduced-motion: reduce)");
    const change = () => {
      reduced = preference.matches;
      if (reduced) {
        effects.forEach(clearTimeout);
        effects.clear();
        layer.replaceChildren();
      }
    };
    preference.addEventListener("change", change);
    const cleanup = stop;
    const observer = new MutationObserver(() => {
      if (!view.isConnected) {
        cleanup();
        preference.removeEventListener("change", change);
        observer.disconnect();
      }
    });
    dispose = () => {
      preference.removeEventListener("change", change);
      observer.disconnect();
    };
    observer.observe(document.getElementById("app")!, {
      childList: true,
      subtree: true,
    });
    await poll();
  }
  return { mount, stop };
}
