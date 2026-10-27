import { badge, button, date, dateTime, esc, heading, icon, table } from "./ui";
import type { State, Site, Certificate } from "./types";
import type { Policy, PolicySummary } from "./policy-page";
import type { Report } from "./dashboard";
import { defaultProtection } from "./dashboard";
import { APIError } from "./api-error";

type Context = {
  api: <T>(path: string) => Promise<T>;
  state: () => State;
};
type Tone = "neutral" | "info" | "success" | "warning" | "danger";
type Status = { label: string; tone: Tone; note: string };
type Issue = { title: string; note: string; action: string };
const link = (href: string, label: string) =>
  `<a class="application-link" href="${href}">${label}${icon("arrow")}</a>`;
const mode = (value?: string) =>
  value === "block" ? "Block" : value === "observe" ? "Observe" : "Off";
const effective = (parent?: string, child?: string) =>
  !parent || parent === "off" || !child || child === "off"
    ? "off"
    : parent === "observe"
      ? "observe"
      : child;
const modeBadge = (value?: string) =>
  badge(
    mode(value),
    value === "block" ? "success" : value === "observe" ? "info" : "neutral",
  );
const selectionCount = (s?: { object_ids: number[]; group_ids: number[] }) =>
  (s?.object_ids?.length || 0) + (s?.group_ids?.length || 0);

function certificateStatus(site: Site, cert?: Certificate): Status {
  if (site.certificate_id === null)
    return {
      label: "HTTP only",
      tone: "warning",
      note: "No TLS certificate assigned",
    };
  if (!cert)
    return {
      label: "Certificate unavailable",
      tone: "danger",
      note: "Review the certificate assignment",
    };
  const until = cert.not_after ? new Date(cert.not_after).getTime() : NaN;
  const from = cert.not_before ? new Date(cert.not_before).getTime() : NaN;
  if (cert.validity === "expired" || until <= Date.now())
    return { label: "Certificate expired", tone: "danger", note: cert.name };
  if (from > Date.now())
    return { label: "Not yet valid", tone: "warning", note: cert.name };
  if (cert.validity !== "valid" || !Number.isFinite(until))
    return { label: "Certificate not ready", tone: "warning", note: cert.name };
  const days = Math.ceil((until - Date.now()) / 86400000);
  return {
    label: days <= 14 ? "Expiring soon" : "TLS valid",
    tone: days <= 14 ? "warning" : "success",
    note: `Expires ${date(cert.not_after)}`,
  };
}

function components(policy: Policy) {
  const s = policy.spec,
    m = s.managed_signatures;
  const signatures = effective(s.mode, m?.set_id ? m.mode : "off");
  const community = s.community_mitigations;
  const communityCount = community?.enabled ? community.rules.length : 0;
  const customCount = s.groups.reduce(
    (n, g) => n + g.rules.filter((r) => !community || !r.feed).length,
    0,
  );
  const network = s.network_access;
  const cidrs =
    (network?.block_cidrs.length || 0) +
    selectionCount(network?.block_addresses);
  const exceptions =
    (m?.excluded_rule_ids.length || 0) + (m?.scoped_exclusions?.length || 0);
  return [
    {
      label: "Request signatures",
      mode: signatures,
      note: m?.set_id
        ? `Paranoia ${m.paranoia_level} · threshold ${m.inbound_threshold}${exceptions ? ` · ${exceptions} exceptions` : ""}`
        : "No signature set selected",
    },
    {
      label: "Response inspection",
      mode: effective(signatures, m?.response_mode),
      note: "Subject to response type and inspection limits",
    },
    {
      label: "HTTP flood",
      mode: s.flood_enabled ? s.mode : "off",
      note: s.flood_enabled
        ? `${s.requests_per_second} req/s per client · ${s.burst} burst`
        : "Rate controls disabled",
    },
    {
      label: "Bot signals",
      mode: s.bot_enabled ? s.mode : "off",
      note: s.bot_challenge?.enabled
        ? "Selective verification configured"
        : "No browser challenge configured",
    },
    {
      label: "Community mitigations",
      mode: communityCount ? s.mode : "off",
      note: `${communityCount} pinned rules`,
    },
    {
      label: "Custom rule groups",
      mode: customCount ? s.mode : "off",
      note: `${customCount} rules · group paths and methods apply`,
    },
    {
      label: "CIDR blocking",
      mode: cidrs ? s.mode : "off",
      note: `${cidrs} ranges / address selections`,
    },
    {
      label: "Geo blocking",
      mode: effective(s.mode, network?.geo_mode),
      note: `${network?.countries.length || 0} countries selected`,
    },
    {
      label: "Connection limits",
      mode: s.connection_limits?.enabled ? s.mode : "off",
      note: "Per application, policy and replica",
    },
  ];
}

export function makeApplications(c: Context) {
  let query = "",
    filter = "all";
  async function mount(view: HTMLElement, id?: number) {
    const state = c.state();
    let policies: Policy[] | null = null;
    try {
      policies = await c.api<Policy[]>("/policies");
    } catch (error) {
      if (error instanceof APIError && error.status === 401) throw error;
    }
    if (!view.isConnected) return;
    const policyFor = (b: PolicySummary) =>
      policies?.find((p) => p.id === b.id && p.revision === b.revision);
    const bindings = (s: Site) =>
      [...(s.policies || [])].sort((a, b) => a.priority - b.priority);
    const certFor = (s: Site) =>
      state.certs.find((cert) => cert.id === s.certificate_id);
    const issues = (s: Site): Issue[] => {
      const result: Issue[] = [],
        tls = certificateStatus(s, certFor(s)),
        assigned = bindings(s);
      if (tls.tone === "warning" || tls.tone === "danger")
        result.push({
          title: tls.label,
          note: tls.note,
          action: certFor(s)
            ? button(
                "view-cert",
                "Review certificate",
                "secondary compact",
                s.certificate_id!,
              )
            : button("edit-site", "Configure TLS", "secondary compact", s.id),
        });
      if (policies === null || assigned.some((b) => !policyFor(b)))
        result.push({
          title: "Protection status unavailable",
          note: "Refresh to load the latest policy configuration.",
          action: button("refresh", "Retry", "secondary compact"),
        });
      else if (!assigned.length)
        result.push({
          title: "No protection policy",
          note: "Local bot/flood settings and any standalone rules apply. Assign a policy for managed signatures.",
          action: link("#policies", "Choose a policy"),
        });
      else if (!assigned.some((b) => !b.source_cidrs.length))
        result.push({
          title: "No default policy",
          note: "Review coverage for clients outside the assigned ranges.",
          action: link("#policies", "Review assignments"),
        });
      else {
        const base = policyFor(assigned.find((b) => !b.source_cidrs.length)!)!;
        const parts = components(base);
        if (base.spec.mode === "off")
          result.push({
            title: "Default policy is off",
            note: "Its protection components are disabled.",
            action: button(
              "edit-policy",
              "Review policy",
              "secondary compact",
              base.id,
            ),
          });
        else if (!parts.some((p) => p.mode !== "off"))
          result.push({
            title: "No active default components",
            note: "The default policy has no enabled protection components.",
            action: button(
              "edit-policy",
              "Review policy",
              "secondary compact",
              base.id,
            ),
          });
      }
      return result;
    };
    const summary = (s: Site) => {
      const assigned = bindings(s),
        base = assigned.find((b) => !b.source_cidrs.length);
      if (policies === null || assigned.some((b) => !policyFor(b)))
        return badge("Unavailable", "warning");
      if (!base)
        return `${badge(assigned.length ? "CIDR policies only" : "Local settings", "neutral")}<small>Flood ${mode(s.protection?.mode)} · bots ${mode(s.protection?.bot_mode)}</small>`;
      const p = policyFor(base)!;
      const signatures = components(p)[0].mode;
      return `${modeBadge(p.spec.mode)}<small>${esc(p.spec.name)}</small><small>Signatures ${mode(signatures)}${assigned.length > 1 ? ` · ${assigned.length - 1} CIDR overrides` : ""}</small>`;
    };

    if (id !== undefined) {
      const site = state.sites.find((s) => s.id === id);
      if (!site) {
        view.innerHTML = `${link("#applications", "All applications")}<section class="empty-state"><h1>Application unavailable</h1><p>It may have been removed. Return to the application list to continue.</p></section>`;
        return;
      }
      const tls = certificateStatus(site, certFor(site)),
        attention = issues(site),
        assigned = bindings(site);
      const local = site.protection || defaultProtection;
      const exemptionCount =
        (local.flood_exempt_cidrs?.length || 0) +
        (local.bot_exempt_cidrs?.length || 0) +
        selectionCount(local.flood_exempt_addresses) +
        selectionCount(local.bot_exempt_addresses);
      view.innerHTML =
        `<div class="application-back">${link("#applications", "All applications")}</div>` +
        heading(
          esc(site.name),
          site.hostnames.map(esc).join(" · "),
          button("refresh", `${icon("refresh")}Refresh`, "secondary") +
            button("edit-site", "Edit application", "primary", site.id),
        ) +
        `<div class="application-status-strip">${badge(site.enabled ? "Routing enabled" : "Routing paused", site.enabled ? "info" : "neutral")}${badge(tls.label, tls.tone)}<span>${site.traffic_profile === "api" ? "API" : site.traffic_profile === "streaming" ? "SSE / streaming API" : "Website"}</span></div>
        <div id="application-activity-summary" class="application-activity-summary" role="status">Loading recorded traffic…</div>
        <nav class="application-sections" aria-label="Application sections"><button type="button" class="text-button" data-application-section="application-routing">Connection</button><button type="button" class="text-button" data-application-section="application-protection">Protection</button><button type="button" class="text-button" data-application-section="application-traffic">Recent traffic</button></nav>
        ${!site.enabled ? '<div class="notice">Routing is paused. The protection settings below are saved but this application is not accepting routed traffic.</div>' : ""}
        ${attention.length ? `<section class="application-attention" aria-label="Needs attention"><h2>Needs attention <span class="count">${attention.length}</span></h2>${attention.map((i) => `<div class="application-issue"><div><h3>${esc(i.title)}</h3><p>${esc(i.note)}</p></div>${i.action}</div>`).join("")}</section>` : ""}
        <div class="application-detail-grid"><section class="application-panel" id="application-routing" tabindex="-1"><div class="section-heading"><h2>Routing &amp; TLS</h2>${button("edit-site", "Edit routing", "secondary compact", site.id)}</div><dl class="application-facts"><div><dt>Public domains</dt><dd>${site.hostnames.map(esc).join("<br>")}</dd></div><div><dt>Upstream</dt><dd class="domain">${esc(site.upstream)}</dd></div><div><dt>Certificate</dt><dd>${esc(certFor(site)?.name || "None assigned")}<small>${esc(tls.note)}</small></dd></div><div><dt>HTTP behavior</dt><dd>${site.redirect_https ? "Redirect to HTTPS" : "HTTP allowed"}</dd></div></dl><p class="muted">Routing enabled describes saved configuration. Use Test upstream in Edit routing to check connectivity; it does not verify public DNS.</p></section>
        <section class="application-panel"><div class="section-heading"><h2>Client identity &amp; exemptions</h2>${button("edit-site", "Review settings", "secondary compact", site.id)}</div><dl class="application-facts"><div><dt>Client IP source</dt><dd>${local.trusted_proxies?.length || selectionCount(local.trusted_addresses) ? esc(local.client_ip_header || "x-forwarded-for") : "Direct connection peer"}</dd></div><div><dt>Trusted proxies</dt><dd>${local.trusted_proxies?.map(esc).join(", ") || "No inline ranges"}<small>${selectionCount(local.trusted_addresses)} address selections</small></dd></div><div><dt>Bot / flood exemptions</dt><dd>${exemptionCount ? `${exemptionCount} ranges / address selections` : "None configured"}</dd></div></dl><p class="muted">Exempt clients can bypass individual components. CIDR policy selection requires a reliable client identity.</p></section></div>
        <section class="application-panel" id="application-protection" tabindex="-1"><div class="section-heading"><div><h2>Protection by client scope</h2><p class="muted">Effective component modes from saved policies. Smaller priorities match first; Observe caps blocking.</p></div>${link("#policies", "Manage assignments")}</div>
        ${
          policies === null
            ? '<div class="simple-empty">Protection could not be loaded. Refresh to try again.</div>'
            : assigned.length
              ? assigned
                  .map((b) => {
                    const p = policyFor(b);
                    if (!p)
                      return `<div class="simple-empty">${esc(b.name)} changed while loading. Refresh for its current protection.</div>`;
                    const network = p.spec.network_access;
                    const allowCount =
                      (network?.allow_cidrs.length || 0) +
                      selectionCount(network?.allow_addresses);
                    const shared = new Set(p.applications.map((a) => a.site_id))
                      .size;
                    return `<article class="application-policy"><div class="section-heading"><div><span class="application-eyebrow">${b.source_cidrs.length ? `Priority ${b.priority} · ${esc(b.source_cidrs.join(", "))}` : "Default · all other clients"}</span><h3>${esc(p.spec.name)} <span class="muted">v${p.revision}</span></h3></div>${button("edit-policy", "Edit policy", "secondary compact", p.id)}</div><div class="application-components">${components(
                      p,
                    )
                      .map(
                        (part) =>
                          `<div><span>${part.label}</span>${modeBadge(part.mode)}<small>${esc(part.note)}</small></div>`,
                      )
                      .join(
                        "",
                      )}</div>${allowCount ? `<p class="application-policy-note">${allowCount} allow ranges / address selections bypass ${network?.allow_scope === "all" ? "all WAF protection" : "Geo checks"} when this policy is active.</p>` : ""}<p class="application-policy-note">Shared by ${shared} application${shared === 1 ? "" : "s"}. Changes apply to every assignment. Body limits, scoped exceptions and request conditions still apply.</p></article>`;
                  })
                  .join("")
              : `<div class="application-local"><h3>Local application settings</h3><p>HTTP flood ${modeBadge(local.mode)} · Bot signals ${modeBadge(local.bot_mode)}</p><p>Managed signatures require an assigned policy. Standalone custom rules are managed in Rules.</p>${link("#rules", "Review standalone rules")}</div>`
        }</section>
        <section class="application-panel" id="application-traffic" tabindex="-1" aria-busy="true"><div class="loading">Loading this application's traffic…</div></section>
        <div class="application-footer"><span class="muted">Saved configuration · gateway version ${state.gateway.configuration_version}. Replica loading may take additional time.</span>${button("delete-site", "Delete application", "danger compact", site.id)}</div>`;
      view
        .querySelectorAll<HTMLButtonElement>("[data-application-section]")
        .forEach((button) => {
          button.addEventListener("click", () => {
            const section = view.querySelector<HTMLElement>(
              "#" + button.dataset.applicationSection,
            )!;
            section.scrollIntoView({ block: "start" });
            section.focus({ preventScroll: true });
          });
        });
      const activity = view.querySelector<HTMLElement>(
        "#application-activity-summary",
      )!;
      const target = view.querySelector<HTMLElement>("#application-traffic")!;
      try {
        const report = await c.api<Report>(
          `/dashboard?site_id=${id}&minutes=15`,
        );
        if (!target.isConnected) return;
        activity.textContent = `${report.totals.requests.toLocaleString()} requests recorded · ${report.totals.blocked.toLocaleString()} blocked · ${report.totals.flagged.toLocaleString()} flagged · last 15 minutes${report.dropped_logs ? " · counts may be incomplete" : ""}`;
        target.innerHTML = `<div class="section-heading"><div><h2>Recent traffic</h2><p class="muted">Last 15 minutes · ${esc(dateTime(report.at))}</p></div>${link(`#dashboard?site_id=${id}`, "Open traffic dashboard")}</div>
          ${report.dropped_logs ? '<div class="notice error">Some access logs were dropped. These counts may be incomplete.</div>' : ""}
          <div class="application-traffic-totals"><div><strong>${report.totals.requests.toLocaleString()}</strong><span>Requests</span></div><div><strong>${report.totals.blocked.toLocaleString()}</strong><span>Blocked</span></div><div><strong>${report.totals.flagged.toLocaleString()}</strong><span>Flagged</span></div></div>
          ${
            report.recent.length
              ? table(
                  ["Time", "Client / method", "Response", "Outcome", ""],
                  report.recent.map((event) => [
                    esc(dateTime(event.at)),
                    `${esc(event.peer)}<small>${esc(event.method)}</small>`,
                    `HTTP ${event.status}`,
                    badge(
                      event.blocked
                        ? "Blocked"
                        : event.signals.length
                          ? "Flagged · allowed"
                          : "Allowed",
                      event.blocked
                        ? "danger"
                        : event.signals.length
                          ? "warning"
                          : "neutral",
                    ),
                    button(
                      "request-details",
                      "View details",
                      "secondary compact",
                      event.id,
                    ),
                  ]),
                  "Application recent requests",
                )
              : `<div class="simple-empty"><h3>No requests recorded in this window</h3><p>Check client DNS, your listener ports and upstream connectivity, then send a request to this application's domain. An empty window does not establish whether it is reachable.</p>${button("edit-site", "Check routing", "secondary compact", id)}</div>`
          }`;
      } catch (error) {
        if (error instanceof APIError && error.status === 401) throw error;
        if (activity.isConnected)
          activity.textContent =
            "Recorded traffic is unavailable. Refresh to try again.";
        if (target.isConnected)
          target.innerHTML = `<h2>Traffic unavailable</h2><p>Request data could not be loaded. Your saved settings are shown above.</p>${button("refresh", "Retry", "secondary")}`;
      } finally {
        target.removeAttribute("aria-busy");
      }
      return;
    }

    const attentionCount = state.sites.filter((s) => issues(s).length).length;
    view.innerHTML =
      heading(
        "Applications",
        "See what is connected, how it is protected, and what needs your attention.",
        button("refresh", `${icon("refresh")}Refresh`, "secondary") +
          button("new-site", `${icon("plus")}Add application`),
      ) +
      `<div class="application-overview-stats"><div><strong>${state.sites.length}</strong><span>Applications</span></div><div><strong>${state.sites.filter((s) => s.enabled).length}</strong><span>Routing enabled</span></div><div><strong>${attentionCount}</strong><span>Need attention</span></div></div>` +
      (!state.sites.length
        ? `<section class="application-panel application-start"><span class="application-eyebrow">YOUR FIRST APPLICATION</span><h2>Connect it. Choose protection. Verify traffic.</h2><p>Bring your domain, upstream address and certificate together, then review what your application receives.</p><ol><li><strong>Prepare TLS</strong><p>Request a certificate or upload one you already have.</p>${button("issue", "Request certificate", "secondary")}${button("upload", "Upload PEM", "subtle")}</li><li><strong>Connect your application</strong><p>Set its domains and upstream, test the connection, and choose an initial policy. Review its mode before saving.</p>${button("new-site", "Add application", "primary")}</li><li><strong>Verify and tune</strong><p>Point client DNS at Aegis, send a request and inspect the result here. Observe records matches while allowing traffic.</p></li></ol></section>`
        : `<div class="application-toolbar"><label class="application-search">Find an application<input type="search" id="application-search" placeholder="Search names, domains or upstreams" value="${esc(query)}"></label><label>Show<select id="application-filter" aria-label="Filter applications"><option value="all">All applications</option><option value="attention">Needs attention</option><option value="paused">Routing paused</option></select></label><span id="application-result-count" class="muted" role="status"></span></div><div id="application-list"></div>`) +
      `<p class="page-note">${icon("shield")}Routing and protection are separate. Open an application to review component modes, client scopes and exceptions.</p>`;
    if (!state.sites.length) return;
    const search = view.querySelector<HTMLInputElement>("#application-search")!;
    const select = view.querySelector<HTMLSelectElement>(
      "#application-filter",
    )!;
    select.value = filter;
    const draw = () => {
      query = search.value;
      filter = select.value;
      const shown = state.sites.filter(
        (s) =>
          [s.name, ...s.hostnames, s.upstream]
            .join(" ")
            .toLowerCase()
            .includes(query.trim().toLowerCase()) &&
          (filter === "all" ||
            (filter === "paused" && !s.enabled) ||
            (filter === "attention" && issues(s).length)),
      );
      view.querySelector("#application-result-count")!.textContent =
        `${shown.length} of ${state.sites.length} applications`;
      view.querySelector("#application-list")!.innerHTML = shown.length
        ? table(
            [
              "Application",
              "Routing & TLS",
              "Default protection",
              "Attention",
              "",
            ],
            shown.map((s) => {
              const tls = certificateStatus(s, certFor(s)),
                attention = issues(s);
              return [
                `<a class="application-name" href="#applications/${s.id}">${esc(s.name)}</a><small class="domain">${s.hostnames.map(esc).join(", ")}</small><small>${s.traffic_profile === "api" ? "API" : s.traffic_profile === "streaming" ? "SSE / streaming" : "Website"}</small>`,
                `${badge(s.enabled ? "Enabled" : "Paused", s.enabled ? "info" : "neutral")}<small>${badge(tls.label, tls.tone)}</small>`,
                summary(s),
                attention.length
                  ? `<span class="application-attention-label">${esc(attention[0].title)}</span>${attention.length > 1 ? `<small>+${attention.length - 1} more to review</small>` : ""}`
                  : '<span class="muted">No attention items</span>',
                `<div class="row-actions">${link(`#applications/${s.id}`, "Open")}${button("edit-site", "Edit", "secondary compact", s.id)}</div>`,
              ];
            }),
            "Applications",
          )
        : '<div class="simple-empty"><h2>No applications match</h2><p>Try another search or choose All applications.</p></div>';
    };
    search.addEventListener("input", draw);
    select.addEventListener("change", draw);
    draw();
  }
  return { mount };
}
