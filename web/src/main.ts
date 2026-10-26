import { botChallengeMarkup, readBotChallenge } from "./bot-challenge";
import { makeLiveMap } from "./live-map";
import { clientAddress } from "./response-status";
import {
  makeAddressObjects,
  emptyInventory,
  type AddressInventory,
} from "./address-objects";
import { makeRequestDetails } from "./request-details";
import { makeSignatureSetsUI, managedSignatureSummary } from "./signature-sets";
import type {
  Site,
  Certificate,
  Account,
  DNSCredential,
  Job,
  Gateway,
  Audit,
  Access,
  State,
} from "./types";
import {
  esc,
  date,
  dateTime,
  icon,
  button,
  badge,
  field,
  check,
  actions,
  names,
  authority,
  heading,
  table,
} from "./ui";
import { APIError } from "./api-error";
import { makeCertificateForms } from "./certificate-forms";
import {
  makePoliciesPage,
  policySummary,
  type PolicySummary,
} from "./policy-page";
import { makeAlertsPage } from "./alerts";
import { makeSystemPage } from "./system";
import { makeAgentAccess } from "./agent-access";
import {
  headerMarkup,
  bindHeaderEditor,
  readHeaders,
  type HeaderSettings,
} from "./headers";
import { protectionOptions, readProtectionOptions } from "./protection-options";
import { makeFeedsUI } from "./feeds";
import {
  makeDashboardUI,
  defaultProtection,
  type Protection,
} from "./dashboard";
import { themeControl, toggleTheme } from "./theme";
import { makePolicyUI } from "./policies";
export {};
const root = document.querySelector<HTMLDivElement>("#app")!;
let addressInventory: AddressInventory = emptyInventory;
let state: State = {
  dns: [],
  sites: [],
  certs: [],
  accounts: [],
  jobs: [],
  gateway: {
    configuration_version: 0,
    database_available: false,
    propagation_seconds: 2,
    dropped_access_logs: 0,
  },
};
let csrf = "",
  username = "",
  page = "certificates",
  epoch = 0,
  polling = false,
  lastSignature = "",
  returnFocus: HTMLElement | null = null;
const newestJob = (id: number) =>
  state.jobs.find((j) => j.certificate_id === id);
async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    signal: AbortSignal.timeout(
      (path === "/acme/accounts" || path === "/geolocation/update") &&
        method === "POST"
        ? 90000
        : path.startsWith("/rule-feeds/") && path.endsWith("/sync")
          ? 45000
          : 20000,
    ),
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "aegis-waf",
      "X-CSRF-Token": csrf,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok)
    throw new APIError(
      data.error || "The request could not be completed.",
      response.status,
    );
  return data as T;
}
async function fetchState(): Promise<State> {
  const [sites, certs, accounts, jobs, gateway, dns] = await Promise.all([
    api<Site[]>("/sites"),
    api<Certificate[]>("/certificates"),
    api<Account[]>("/acme/accounts"),
    api<Job[]>("/acme/jobs"),
    api<Gateway>("/status"),
    api<DNSCredential[]>("/dns/credentials"),
  ]);
  addressInventory = await addressUI.load();
  return { sites, certs, accounts, jobs, gateway, dns };
}
function notice(message: string, error = false) {
  const area =
    document.querySelector<HTMLDivElement>("#editor[open] #form-message") ||
    document.querySelector<HTMLDivElement>("#message");
  if (area)
    area.innerHTML = `<div class="notice ${error ? "error" : ""}" role="${error ? "alert" : "status"}">${icon(error ? "activity" : "check")}<span>${esc(message)}</span></div>`;
}
async function handleError(error: unknown) {
  if (error instanceof APIError && error.status === 401) {
    username = "";
    csrf = "";
    epoch++;
    await start();
    notice("Your session ended. Sign in to continue.", true);
  } else
    notice(
      error instanceof Error
        ? error.message
        : "Something went wrong. Please try again.",
      true,
    );
}
function formHandler(id: string, submit: (data: FormData) => Promise<void>) {
  const form = document.getElementById(id) as HTMLFormElement;
  let busy = false;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy) return;
    busy = true;
    const submitButton = form.querySelector<HTMLButtonElement>(
      "button[type=submit]",
    )!;
    submitButton.disabled = true;
    submitButton.textContent = "Please wait…";
    form.setAttribute("aria-busy", "true");
    try {
      await submit(new FormData(form));
    } catch (error) {
      await handleError(error);
    } finally {
      busy = false;
      form.removeAttribute("aria-busy");
      submitButton.disabled = false;
      submitButton.textContent = submitButton.dataset.label || "Save";
    }
  });
}
function currentPage() {
  const aliases: Record<string, string> = {
    overview: "dashboard",
    sites: "proxy-hosts",
    acme: "authorities",
  };
  const raw = location.hash.slice(1) || "dashboard";
  return (
    aliases[raw] ||
    ([
      "alerts",
      "system",
      "address-objects",
      "policies",
      "ai",
      "rule-feeds",
      "signature-sets",
      "live-map",
      "dashboard",
      "certificates",
      "proxy-hosts",
      "authorities",
      "activity",
      "rules",
      "traffic",
    ].includes(raw)
      ? raw
      : "certificates")
  );
}
function shell() {
  const nav = [
    ["dashboard", "activity", "Dashboard"],
    ["certificates", "certificate", "Certificates"],
    ["proxy-hosts", "globe", "Proxy hosts"],
    ["address-objects", "globe", "Address objects"],
    ["rules", "shield", "Rules"],
    ["policies", "shield", "Policies"],
    ["ai", "activity", "Agent access"],
    ["traffic", "activity", "Traffic"],
    ["activity", "activity", "Activity"],
    ["alerts", "activity", "Alerts"],
    ["system", "activity", "System"],
  ];
  root.innerHTML = `<div class="app-shell"><aside class="sidebar"><a class="brand" href="#certificates">${icon("shield")}<span>Aegis<span class="brand-suffix">WAF</span></span></a><div class="nav-label">WORKSPACE</div><nav aria-label="Main navigation">${nav.map(([id, i, label]) => `<a href="#${id}" ${page === id || (id === "rules" && (page === "rule-feeds" || page === "signature-sets")) ? 'aria-current="page"' : ""}>${icon(i)}<span>${label}</span>${id === "certificates" && state.certs.length ? `<span class="nav-count" aria-hidden="true">${state.certs.length}</span>` : ""}</a>`).join("")}<div class="nav-divider"></div><a href="#authorities" ${page === "authorities" ? 'aria-current="page"' : ""}>${icon("key")}<span>Certificate authorities</span></a></nav><div class="sidebar-footer"><div class="avatar">${esc(username.slice(0, 1).toUpperCase())}</div><div><strong>${esc(username)}</strong><small>Administrator</small></div><button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icon("logout")}</button></div></aside><div class="workspace"><header class="topbar"><span>Workspace <span class="breadcrumb">/</span> <strong>${{ "live-map": "Live traffic map", "address-objects": "Address objects", "rule-feeds": "Rules", "signature-sets": "Rules", policies: "Policies", alerts: "Alerts", system: "System", ai: "Agent access", dashboard: "Dashboard", certificates: "Certificates", "proxy-hosts": "Proxy hosts", authorities: "Certificate authorities", activity: "Activity", rules: "Rules", traffic: "Traffic" }[page]}</strong></span><div class="header-tools">${themeControl()}<div id="connection" class="connection"><span></span>Gateway connected</div></div></header><main id="content"><div id="message" aria-live="polite"></div><div id="view"><div class="loading">Loading workspace…</div></div></main><footer class="workspace-footer"><span>Aegis WAF · Self-hosted application gateway</span><span>Certificate management & reverse proxy</span></footer></div></div><dialog id="editor" aria-labelledby="editor-title"></dialog>`;
  document.getElementById("editor")!.addEventListener("close", () => {
    if (returnFocus?.isConnected) returnFocus.focus();
  });
}
function onboarding() {
  const ready = state.certs.some((c) => c.validity === "valid"),
    connected = state.sites.some((s) => s.enabled && s.certificate_id !== null);
  if (ready && connected) return "";
  return `<section class="onboarding" aria-label="Getting started"><div class="onboarding-title">A secure connection in two steps<small>Start with a certificate. Then connect your application.</small></div><div class="setup-step ${ready ? "complete" : ""}"><span>${ready ? icon("check") : "1"}</span><div><strong>Get a certificate</strong><small>${ready ? "Your certificate is ready." : "Issue with ACME or upload a PEM."}</small></div></div><div class="step-divider"></div><div class="setup-step ${connected ? "complete" : ""}"><span>${connected ? icon("check") : "2"}</span><div><strong>Connect a proxy host</strong><small>${connected ? "Your application is connected." : "Choose a domain and upstream."}</small></div></div></section>`;
}
function certStatus(c: Certificate) {
  const job = newestJob(c.id);
  if (c.validity === "valid") {
    const days = Math.ceil(
      (new Date(c.not_after!).getTime() - Date.now()) / 86400000,
    );
    return badge(
      days <= 14 ? "Expiring soon" : "Valid",
      days <= 14 ? "warning" : "success",
    );
  }
  if (job?.status === "retry") return badge("Needs attention", "danger");
  if (job?.status === "running") return badge("Issuing", "info");
  return badge(
    c.validity === "pending" ? "Queued" : c.validity,
    c.validity === "pending" ? "info" : "danger",
  );
}
function certificateList() {
  if (!state.certs.length)
    return `<section class="empty-state"><div class="empty-icon">${icon("certificate")}</div><h2>Your first certificate starts here</h2><p>Request a certificate with automatic renewal,<br class="desktop-only"> or bring your own certificate and private key.</p><div class="empty-note">${icon("key")}Private keys stay encrypted and never leave the server.</div></section>`;
  return table(
    ["Certificate", "Status", "Expires", "Renewal", ""],
    state.certs.map((c) => {
      const job = newestJob(c.id);
      return [
        `<div class="resource"><span class="resource-icon">${icon("certificate")}</span><div><button class="text-button" data-action="view-cert" data-id="${c.id}">${esc(c.name)}</button><small class="domain">${c.domains.map(esc).join(", ")}</small>${c.assigned_sites.length ? `<small>${c.assigned_sites.length} connected ${c.assigned_sites.length === 1 ? "site" : "sites"}</small>` : ""}</div></div>`,
        `${certStatus(c)}${job?.status === "retry" ? `<small class="error-text">${esc(job.error)}</small>` : ""}`,
        `<span>${esc(date(c.not_after))}</span>${c.not_after ? `<small>${Math.max(0, Math.ceil((new Date(c.not_after).getTime() - Date.now()) / 86400000))} days remaining</small>` : ""}`,
        c.origin === "acme"
          ? `<span class="renewal">${icon("refresh")}Automatic</span><small>ACME managed</small>`
          : "<span>Manual</span><small>Uploaded PEM</small>",
        `<div class="row-actions">${c.validity === "valid" && !c.assigned_sites.length ? button("connect", "Connect site", "secondary compact", c.id) : ""}${job?.status === "retry" ? button("retry", "Retry", "secondary compact", job.id) : ""}${button("view-cert", "Details", "subtle compact", c.id)}</div>`,
      ];
    }),
    "Certificates",
  );
}
function jobsList() {
  if (!state.jobs.length) return "";
  return `<section class="section"><div class="section-heading"><div><h2>Issuance & renewal</h2><p>Live status from your certificate authority.</p></div><span class="live-caption"><span></span>Updates automatically</span></div><div class="job-list">${state.jobs
    .slice(0, 8)
    .map(
      (j) =>
        `<article class="job-row"><div class="job-icon ${j.status === "retry" ? "warning" : ""}">${icon(j.status === "succeeded" ? "check" : j.status === "retry" ? "activity" : "clock")}</div><div class="job-copy"><strong>${esc(j.name)}</strong><small>${j.status === "succeeded" ? "Certificate issued. Ready to connect to a proxy host." : j.status === "queued" ? "Queued. The certificate worker will start shortly." : j.status === "running" ? "Your authority is validating domains and preparing the certificate." : esc(j.error)}</small>${j.status === "retry" ? `<small>Attempt ${j.attempts} · Next retry ${esc(dateTime(j.next_attempt))}</small>` : ""}</div>${badge(({ succeeded: "Issued", queued: "Queued", running: "In progress", retry: "Retry scheduled" } as Record<string, string>)[j.status] || j.status, j.status === "succeeded" ? "success" : j.status === "retry" ? "warning" : "info")}${j.status === "retry" ? button("retry", "Retry now", "secondary compact", j.id) : ""}</article>`,
    )
    .join("")}</div></section>`;
}
function sitesList() {
  if (!state.sites.length)
    return `<section class="empty-state"><div class="empty-icon">${icon("globe")}</div><h2>Connect your first application</h2><p>A proxy host connects a public domain to your application.<br class="desktop-only"> Attach a certificate to serve it securely over HTTPS.</p>${button("new-site", `${icon("plus")}Add proxy host`)}</section>`;
  return table(
    ["Proxy host", "Upstream", "Certificate", "Status", ""],
    state.sites.map((s) => [
      `<div class="resource"><span class="resource-icon">${icon("globe")}</span><div><strong>${esc(s.name)}</strong><small class="domain">${s.hostnames.map(esc).join(", ")}</small></div></div>`,
      `<span class="domain">${esc(s.upstream)}</span><small>${s.traffic_profile === "streaming" ? "SSE / streaming" : s.traffic_profile === "api" ? "API" : "Website"} · ${s.redirect_https ? "HTTP → HTTPS" : "HTTP allowed"} · ${s.preserve_host ? "Original host header" : "Upstream host header"}</small>`,
      esc(
        state.certs.find((c) => c.id === s.certificate_id)?.name || "HTTP only",
      ),
      badge(
        s.enabled ? "Enabled" : "Disabled",
        s.enabled ? "success" : "neutral",
      ),
      `<div class="row-actions">${button("edit-site", "Edit", "secondary compact", s.id)}${button("delete-site", "Delete", "danger compact", s.id)}</div>`,
    ]),
    "Proxy hosts",
  );
}
async function render() {
  const view = document.getElementById("view");
  if (!view) return;
  document.title = `${({ "live-map": "Live traffic map", "address-objects": "Address objects", "rule-feeds": "Rules", "signature-sets": "Rules", policies: "Policies", alerts: "Alerts", system: "System", ai: "Agent access", dashboard: "Dashboard", certificates: "Certificates", "proxy-hosts": "Proxy hosts", authorities: "Certificate authorities", activity: "Activity", rules: "Rules", traffic: "Traffic" } as Record<string, string>)[page]} · Aegis WAF`;
  if (page === "dashboard") await dashboardUI.mount(view, state.sites);
  if (page === "policies") {
    const stamp = epoch;
    const html = await policyPage.render();
    if (stamp === epoch) view.innerHTML = html;
  }
  if (page !== "live-map") liveMapUI.stop();
  if (page === "live-map") await liveMapUI.mount(view);
  if (page === "ai") await aiPage.render(view);
  if (page === "system") await systemPage.render(view);
  if (page === "alerts") await alertsPage.render(view);
  if (page === "address-objects") {
    const stamp = epoch;
    const html = await addressUI.render();
    if (stamp === epoch) view.innerHTML = html;
  }
  if (page === "signature-sets") {
    const stamp = epoch;
    const html = await signatureSetsUI.render();
    if (stamp === epoch) view.innerHTML = html;
  }
  if (page === "rule-feeds") {
    const stamp = epoch;
    const html = await feedsUI.render();
    if (stamp === epoch) view.innerHTML = html;
  }
  if (page === "certificates")
    view.innerHTML =
      heading(
        "Certificates",
        "Secure your domains. Let ACME take care of renewal.",
        button("upload", `${icon("upload")}Upload PEM`, "secondary") +
          button("issue", `${icon("plus")}Request certificate`),
      ) +
      onboarding() +
      `<section class="inventory"><div class="inventory-heading"><h2>Certificate inventory <span class="count">${state.certs.length}</span></h2><span class="muted">${state.certs.filter((c) => c.origin === "acme").length} automatically managed</span></div><div id="certificate-list">${certificateList()}</div></section><div id="job-list">${jobsList()}</div><div class="page-note">${icon("shield")}ACME certificates renew automatically before they expire. Existing certificates stay active during retries.</div>`;
  if (page === "proxy-hosts")
    view.innerHTML =
      heading(
        "Proxy hosts",
        "Route your domains to the applications behind them.",
        button("new-site", `${icon("plus")}Add proxy host`),
      ) +
      `<div class="route-guide"><span>Public domain</span>${icon("arrow")}<span class="route-active">${icon("shield")}Aegis WAF · TLS</span>${icon("arrow")}<span>Your upstream</span></div><div id="site-list">${sitesList()}</div><div class="page-note">${icon("clock")}Saved changes reach every gateway replica within 2 seconds.</div>`;
  if (page === "authorities")
    view.innerHTML =
      heading(
        "Certificate authorities",
        "Accounts used to request and renew your ACME certificates.",
        button("new-account", `${icon("plus")}Add authority`),
      ) +
      (!state.accounts.length
        ? `<section class="empty-state"><div class="empty-icon">${icon("key")}</div><h2>Choose your certificate authority</h2><p>Connect to Let’s Encrypt or a custom ACME server.<br class="desktop-only"> You’ll review its terms before creating an account.</p>${button("new-account", "Set up ACME")}</section>`
        : `<div class="authority-list">${state.accounts.map((a) => `<article class="authority-card"><span class="resource-icon">${icon("key")}</span><div><h2>${esc(authority(a))}</h2><p>${esc(a.email)}</p><span class="domain muted">${esc(a.directory)}</span><small>Terms accepted ${esc(date(a.tos_accepted_at))}</small></div>${badge(a.directory.includes("staging") ? "Test certificates" : "Registered", a.directory.includes("staging") ? "warning" : "success")}</article>`).join("")}</div>`) +
      `<div class="info-panel"><h3>Start with staging</h3><p>Use Let’s Encrypt staging to check DNS and HTTP-01 reachability. Switch to production for certificates trusted by browsers.</p></div><section class="section"><div class="section-heading"><div><h2>DNS providers</h2><p>Cloudflare DNS-01 verifies domains without inbound port 80.</p></div>${button("new-dns", "Connect Cloudflare", "secondary")}</div>${
        state.dns.length
          ? table(
              ["Name", "Provider", ""],
              state.dns.map((d) => [
                esc(d.name),
                "Cloudflare",
                `<div class="row-actions">${button("edit-dns", "Edit", "secondary compact", d.id)}${button("delete-dns", "Delete", "danger compact", d.id)}</div>`,
              ]),
              "DNS providers",
            )
          : '<div class="simple-empty">Connect a scoped Cloudflare API token, then select DNS-01 when requesting a certificate.</div>'
      }</section>`;
  if (page === "activity") {
    view.innerHTML =
      heading(
        "Activity",
        "Administrative changes and recent requests to your applications.",
        button("refresh", `${icon("refresh")}Refresh`, "secondary"),
      ) + '<div class="loading">Loading activity…</div>';
    const stamp = epoch;
    const [audit, access] = await Promise.all([
      api<Audit[]>("/audit"),
      api<Access[]>("/access-logs"),
    ]);
    if (stamp !== epoch || page !== "activity") return;
    view.innerHTML =
      heading(
        "Activity",
        "Administrative changes and recent requests to your applications.",
        button("refresh", `${icon("refresh")}Refresh`, "secondary"),
      ) +
      `<section class="section"><div class="section-heading"><h2>Administrative audit</h2><span class="muted">Latest 200 events</span></div>${
        audit.length
          ? table(
              ["Time", "Administrator", "Action", "Resource"],
              audit.map((a) => [
                esc(dateTime(a.at)),
                esc(a.actor),
                esc(a.action),
                esc(a.resource),
              ]),
              "Administrative audit",
            )
          : '<div class="simple-empty">Administrative changes will appear here.</div>'
      }</section><section class="section"><div class="section-heading"><h2>Application requests</h2><span class="muted">Latest 200 requests</span></div>${
        access.length
          ? table(
              [
                "Time",
                "Site / sender",
                "Request",
                "Rule outcomes",
                "Duration",
                "",
              ],
              access.map((a) => [
                esc(dateTime(a.at)),
                `${a.site_id}<div>${clientAddress(a.peer, a.client_objects)}</div>${a.policy_name ? `<small>${esc(a.policy_name)} · v${a.policy_revision}</small>` : ""}${managedSignatureSummary(a.managed_signatures, esc)}`,
                `${esc(a.method)} · ${a.status}`,
                [
                  ...(a.rule_results || []).map(
                    (r) =>
                      `#${r.rule_id} · ${esc(r.action)} · ${esc(r.result)}`,
                  ),
                  ...(a.protection_exemptions || []).map((v) =>
                    esc(
                      v === "http_flood"
                        ? "HTTP flood exempt"
                        : v === "anti_bot"
                          ? "Anti-bot exempt"
                          : v,
                    ),
                  ),
                ].join("<br>") || "—",
                `${a.duration_ms} ms`,
                `<button type="button" class="secondary compact" data-action="request-details" data-id="${a.id}">View details</button>`,
              ]),
              "Application requests",
            )
          : '<div class="simple-empty">Requests appear after a proxy host starts receiving traffic.</div>'
      }</section>`;
  }
  if (page === "rules" || page === "traffic") {
    const stamp = epoch;
    view.innerHTML = '<div class="loading">Loading policy workspace…</div>';
    const html =
      page === "rules"
        ? await policyUI.renderRules()
        : await policyUI.renderTraffic();
    if (stamp !== epoch) return;
    view.innerHTML = html;
  }
  updateConnection();
}
function updateConnection(degraded = false) {
  const el = document.getElementById("connection");
  if (!el) return;
  el.classList.toggle(
    "degraded",
    degraded || !state.gateway.database_available,
  );
  el.innerHTML = `<span></span>${degraded ? "Connection interrupted" : state.gateway.database_available ? "Gateway connected" : "Database unavailable"}`;
}
async function refresh() {
  page = currentPage();
  const stamp = ++epoch;
  shell();
  try {
    const next = await fetchState();
    if (stamp !== epoch || !username) return;
    state = next;
    lastSignature = JSON.stringify(next);
    await render();
  } catch (error) {
    if (stamp !== epoch) return;
    const view = document.getElementById("view");
    if (view)
      view.innerHTML = `<div class="empty-state"><h2>Workspace unavailable</h2><p>Check the gateway’s database connection and try again.</p>${button("refresh", "Try again", "secondary")}</div>`;
    await handleError(error);
  }
}
async function poll() {
  if (
    polling ||
    !username ||
    document.hidden ||
    (document.getElementById("editor") as HTMLDialogElement | null)?.open ||
    page === "activity" ||
    page === "traffic" ||
    page === "live-map" ||
    page === "ai" ||
    page === "system" ||
    page === "alerts"
  )
    return;
  polling = true;
  const stamp = epoch;
  try {
    if (page === "dashboard") {
      await dashboardUI.update();
      updateConnection();
      return;
    }
    const next = await fetchState();
    if (
      stamp !== epoch ||
      !username ||
      (document.getElementById("editor") as HTMLDialogElement | null)?.open
    )
      return;
    state = next;
    updateConnection();
    const signature = JSON.stringify(next);
    if (
      signature !== lastSignature ||
      page === "rules" ||
      page === "rule-feeds" ||
      page === "signature-sets" ||
      page === "policies"
    ) {
      lastSignature = signature;
      const focus = document.activeElement as HTMLElement;
      const focusAction = focus?.dataset.action,
        focusID = focus?.dataset.id;
      await render();
      if (focusAction) {
        const target = document.querySelector<HTMLElement>(
          `button[data-action="${CSS.escape(focusAction)}"]${focusID ? `[data-id="${CSS.escape(focusID)}"]` : ""}`,
        );
        target?.focus();
      }
    }
  } catch (error) {
    if (stamp !== epoch) return;
    if (error instanceof APIError && error.status === 401)
      await handleError(error);
    else updateConnection(true);
  } finally {
    polling = false;
  }
}
function openEditor(title: string, html: string, step = 0) {
  const dialog = document.getElementById("editor") as HTMLDialogElement;
  if (!dialog.open) returnFocus = document.activeElement as HTMLElement;
  dialog.innerHTML = `<div class="dialog-heading"><div>${step ? `<div class="step-label">STEP ${step} OF 2 · ${step === 1 ? "AUTHORITY" : "DOMAINS"}</div>` : ""}<h2 id="editor-title">${esc(title)}</h2></div><button class="icon-button" data-action="cancel" aria-label="Close dialog">${icon("close")}</button></div><div id="form-message" aria-live="polite"></div><div class="dialog-body">${html}</div>`;
  if (!dialog.open) dialog.showModal();
  dialog.querySelector<HTMLElement>("input,select,textarea")?.focus();
}
function closeEditor() {
  (document.getElementById("editor") as HTMLDialogElement | null)?.close();
}
function siteProtectionMarkup(p: Protection, policies: PolicySummary[] = []) {
  const mode = (name: string, label: string, value: string) =>
    `<label class="field" for="site-${name}">${label}</label><select id="site-${name}" name="${name}">${["off", "observe", "block"].map((m) => `<option value="${m}" ${m === value ? "selected" : ""}>${m === "off" ? "Off" : m === "observe" ? "Observe · log and allow" : "Block · reject matching requests"}</option>`).join("")}</select>`;
  return `<div class="form-divider"></div><h3>Application protection</h3>${policySummary(policies, esc)}<div ${policies.length ? "hidden" : ""}><p class="muted">Choose protection for this application. Observe helps you check impact before blocking.</p>${mode("flood_mode", "HTTP flood protection", p.mode)}<div id="site-flood-rates" ${p.mode === "off" ? "hidden" : ""}>${field("client_rate", "Requests / second per client", String(p.requests_per_second), "number", 'required min="1" max="100000"')}${field("client_burst", "Client burst allowance", String(p.burst), "number", 'required min="1" max="1000000"')}${field("application_rate", "Requests / second per application", String(p.site_requests_per_second), "number", 'required min="1" max="1000000"')}${field("application_burst", "Application burst allowance", String(p.site_burst), "number", 'required min="1" max="2000000"')}<small>Rate budgets follow System rate-state settings: Local is per replica; Redis/Dragonfly is shared. Burst must be at least the configured requests per second.</small></div>${mode("bot_mode", "Anti-bot protection", p.bot_mode)}<small>Observe first and tune for your application; legitimate tools can look automated.</small>${botChallengeMarkup(p.bot_challenge)}</div><details class="advanced"><summary>Client identity, trusted proxies and exemptions</summary><div ${policies.length ? "hidden" : ""}>${check("empty_user_agent", "Flag requests without a User-Agent header", p.block_empty_user_agent)}</div>${protectionOptions(p, addressInventory)}</details>`;
}
async function siteForm(site?: Site, certificate?: Certificate) {
  const initialPolicies = site
    ? []
    : await api<{ id: number; spec: { name: string; mode: string } }[]>(
        "/policies",
      );
  const c = site
    ? state.certs.find((c) => c.id === site.certificate_id)
    : certificate;
  openEditor(
    site ? "Edit proxy host" : "Connect an application",
    `<p class="form-intro">Choose the domain visitors will use and the address where your application runs.</p><form id="site-form">${field("name", "Name", site?.name || c?.name || "", "text", 'required maxlength="120" placeholder="My application"')}${field("hostnames", "Domains", site?.hostnames.join(", ") || c?.domains.filter((h) => !h.includes("*")).join(", ") || "", "text", 'required placeholder="app.example.com"')}<small>Separate multiple domains with commas.</small>${field("upstream", "Upstream URL", site?.upstream || "", "url", 'required placeholder="http://192.168.1.20:3000"')}<label class="field" for="site-traffic-profile">Endpoint type</label><select id="site-traffic-profile" name="traffic_profile"><option value="web" ${!site?.traffic_profile || site.traffic_profile === "web" ? "selected" : ""}>Website · browser protection and optional CAPTCHA</option><option value="api" ${site?.traffic_profile === "api" ? "selected" : ""}>API · JSON denials, no browser CAPTCHA</option><option value="streaming" ${site?.traffic_profile === "streaming" ? "selected" : ""}>SSE / streaming API · immediate chunk forwarding</option></select><small>Policies control signatures and body limits for every type. Website supports selective CAPTCHA. API and SSE return JSON denials without browser challenges or browser-header scoring. API responses use optional bounded inspection; SSE forwards chunks immediately and inspections can stop future output, not recall sent bytes. Binary gRPC and WebSocket messages are not body-inspected.</small>${field("stream_window_bytes", "Streaming inspection window (bytes)", String(site?.stream_window_bytes || 8192), "number", 'required min="4096" max="65536"')}<div class="form-divider"></div><label class="field" for="site-certificate">TLS certificate</label><select id="site-certificate" name="certificate_id"><option value="">HTTP only · no certificate</option>${state.certs
      .filter((v) => v.validity === "valid" || v.id === site?.certificate_id)
      .map(
        (v) =>
          `<option value="${v.id}" ${v.id === c?.id ? "selected" : ""}>${esc(v.name)} · ${esc(v.domains.join(", "))}${v.validity !== "valid" ? " (expired)" : ""}</option>`,
      )
      .join(
        "",
      )}</select>${check("redirect_https", "Redirect HTTP to HTTPS", site?.redirect_https ?? Boolean(c), c ? "" : "disabled")}${!site ? `<label class="field">Initial protection policy<select name="initial_policy_id" aria-label="Initial protection policy"><option value="">Local application settings · no policy assignment</option>${initialPolicies.map((p) => `<option value="${p.id}">${esc(p.spec.name)} · ${esc(p.spec.mode)}</option>`).join("")}</select></label><small>Choose Baseline protection for the included CRS policy, or keep local settings. Policy assignment replaces local bot/flood and standalone-rule activation. Manage later assignments in Policies.</small>` : ""}${siteProtectionMarkup(site?.protection || defaultProtection, site?.policies || [])}${headerMarkup(site?.headers)}<details class="advanced"><summary>Advanced settings</summary>${check("preserve_host", "Preserve the original Host header", site?.preserve_host ?? true)}${check("enabled", "Enable routing", site?.enabled ?? true)}</details>${actions("Save proxy host")}</form>`,
  );
  const select = document.getElementById(
    "site-certificate",
  ) as HTMLSelectElement;
  select.addEventListener("change", () => {
    const redirect = document.querySelector<HTMLInputElement>(
      "[name=redirect_https]",
    )!;
    redirect.disabled = !select.value;
    redirect.checked = Boolean(select.value);
  });
  document
    .getElementById("site-flood_mode")!
    .addEventListener("change", (e) => {
      document.getElementById("site-flood-rates")!.hidden =
        (e.target as HTMLSelectElement).value === "off";
    });
  bindHeaderEditor(document.getElementById("site-form") as HTMLFormElement);
  formHandler("site-form", async (f) => {
    await api("/sites" + (site ? "/" + site.id : ""), site ? "PUT" : "POST", {
      ...(!site
        ? { initial_policy_id: Number(f.get("initial_policy_id")) || 0 }
        : {}),
      name: f.get("name"),
      hostnames: names(f.get("hostnames")),
      upstream: f.get("upstream"),
      traffic_profile: f.get("traffic_profile"),
      stream_window_bytes: Number(f.get("stream_window_bytes")),
      certificate_id: f.get("certificate_id")
        ? Number(f.get("certificate_id"))
        : null,
      redirect_https: f.has("redirect_https"),
      preserve_host: f.has("preserve_host"),
      enabled: f.has("enabled"),
      headers: readHeaders(
        document.getElementById("site-form") as HTMLFormElement,
      ),
      protection: {
        mode: String(f.get("flood_mode")),
        bot_mode: String(f.get("bot_mode")),
        bot_challenge: readBotChallenge(f),
        requests_per_second: Number(f.get("client_rate")),
        burst: Number(f.get("client_burst")),
        site_requests_per_second: Number(f.get("application_rate")),
        site_burst: Number(f.get("application_burst")),
        block_empty_user_agent: f.has("empty_user_agent"),
        ...readProtectionOptions(f),
      },
    });
    closeEditor();
    await refresh();
    notice("Proxy host saved. Your gateway will apply it within 2 seconds.");
  });
}
root.addEventListener("click", async (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>(
    "button[data-action]",
  );
  if (!b) return;
  const action = b.dataset.action,
    id = Number(b.dataset.id);
  try {
    if (await addressUI.handle(action, id)) return;
    if (await policyPage.handle(action, id, b)) return;
    if (await signatureSetsUI.handle(action, b.dataset.id || "")) return;
    if (await feedsUI.handle(action, id)) return;
    if (await policyUI.handleAction(action, id, b.dataset.id)) return;
    switch (action) {
      case "live-map":
        location.hash = "live-map";
        break;
      case "request-details":
        await requestDetails(id);
        break;
      case "protection":
        await dashboardUI.protectionForm();
        break;
      case "geo-sync":
        await dashboardUI.geoSyncForm();
        break;
      case "geo-update":
        dashboardUI.geoForm();
        break;
      case "toggle-theme":
        toggleTheme();
        break;
      case "new-dns":
        dnsCredentialForm();
        break;
      case "edit-dns":
        dnsCredentialForm(state.dns.find((d) => d.id === id));
        break;
      case "delete-dns":
        if (confirm("Delete this Cloudflare credential?")) {
          await api(`/dns/credentials/${id}`, "DELETE");
          await refresh();
          notice("Cloudflare credential deleted.");
        }
        break;
      case "cancel":
        closeEditor();
        break;
      case "logout":
        await api("/logout", "POST", {});
        username = "";
        csrf = "";
        epoch++;
        await start();
        break;
      case "refresh":
        await refresh();
        break;
      case "issue":
        issueForm();
        break;
      case "new-account":
        accountForm();
        break;
      case "review-terms":
        await loadTerms(
          document.getElementById("issue-form") ? "issue-form" : "account-form",
        );
        break;
      case "new-site":
        await siteForm();
        break;
      case "edit-site":
        await siteForm(state.sites.find((s) => s.id === id));
        break;
      case "connect": {
        const c = state.certs.find((c) => c.id === id);
        if (page !== "proxy-hosts") {
          closeEditor();
          history.pushState(null, "", "#proxy-hosts");
          await refresh();
        }
        await siteForm(undefined, c);
        break;
      }
      case "upload":
        uploadForm();
        break;
      case "replace":
        uploadForm(state.certs.find((c) => c.id === id));
        break;
      case "view-cert": {
        const c = state.certs.find((c) => c.id === id);
        if (c) certificateDetails(c);
        break;
      }
      case "renew-cert":
        b.disabled = true;
        await api(`/certificates/${id}/renew`, "POST", {});
        closeEditor();
        await refresh();
        notice(
          "Renewal queued. Your current certificate remains active until a replacement is ready.",
        );
        break;
      case "retry":
        b.disabled = true;
        await api(`/acme/jobs/${id}/retry`, "POST", {});
        closeEditor();
        await refresh();
        notice("Retry queued. Progress will update automatically.");
        break;
      case "delete-site":
      case "delete-cert":
        if (
          confirm(
            action === "delete-site"
              ? "Delete this proxy host and stop routing its traffic?"
              : "Delete this certificate? Attached certificates must be disconnected first.",
          )
        ) {
          await api(
            `/${action === "delete-site" ? "sites" : "certificates"}/${id}`,
            "DELETE",
          );
          closeEditor();
          await refresh();
          notice(
            action === "delete-site"
              ? "Proxy host deleted."
              : "Certificate deleted.",
          );
        }
        break;
      case "reconnect":
        await start();
        break;
    }
  } catch (error) {
    await handleError(error);
  } finally {
    b.disabled = false;
  }
});
const {
  uploadForm,
  dnsCredentialForm,
  accountForm,
  loadTerms,
  issueForm,
  certificateDetails,
} = makeCertificateForms({
  state: () => state,
  reloadState: async () => {
    state = await fetchState();
  },
  currentPage: () => page,
  handleError,
  api,
  openEditor,
  closeEditor,
  formHandler,
  refresh,
  notice,
  certStatus,
  newestJob,
});
const policyPage = makePoliciesPage({
  api,
  sites: () => state.sites,
  esc,
  heading,
  table,
  openEditor,
  closeEditor,
  formHandler,
  refresh,
  notice,
});
const requestDetails = makeRequestDetails({ api, esc, table, openEditor });
const alertsPage = makeAlertsPage({
  api,
  formHandler,
  notice,
  handleError,
  openEditor,
  closeEditor,
});
const systemPage = makeSystemPage({ api, formHandler, notice, handleError });
const aiPage = makeAgentAccess({
  api,
  notice,
  handleError,
  openEditor,
  formHandler,
  closeEditor,
});
const signatureSetsUI = makeSignatureSetsUI({
  closeEditor,
  formHandler,
  api,
  esc,
  heading,
  table,
  refresh,
  notice,
  openEditor,
  applyToPolicy: (set) => policyPage.applySignatureSet(set),
});
const feedsUI = makeFeedsUI({
  api,
  sites: () => state.sites,
  esc,
  heading,
  table,
  openEditor,
  closeEditor,
  formHandler,
  refresh,
  notice,
});
const dashboardUI = makeDashboardUI({
  api,
  esc,
  heading,
  table,
  openEditor,
  closeEditor,
  formHandler,
  notice,
  handleError,
});
window.addEventListener("hashchange", () => {
  if (username) void refresh();
});
setInterval(() => void poll(), 4000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) void poll();
});
async function start() {
  root.innerHTML =
    '<main class="auth-loading">Connecting to your gateway…</main>';
  try {
    const setup = await api<{ setup_required: boolean }>("/setup");
    if (!setup.setup_required) {
      try {
        const me = await api<{ username: string; csrf: string }>("/me");
        username = me.username;
        csrf = me.csrf;
        await refresh();
        return;
      } catch (error) {
        if (!(error instanceof APIError) || error.status !== 401) throw error;
      }
    }
    document.title = setup.setup_required
      ? "Set up your gateway · Aegis WAF"
      : "Sign in · Aegis WAF";
    root.innerHTML = `<div class="auth-shell"><aside class="auth-story"><a href="#certificates" class="brand">${icon("shield")}<span>Aegis<span class="brand-suffix">WAF</span></span></a><div><div class="eyebrow">YOUR APPLICATIONS. YOUR EDGE.</div><h2>A secure home for<br>every application.</h2><p>Manage your certificates.<br>Connect your domains.<br>Keep your infrastructure yours.</p></div><small>Self-hosted · Certificate management & reverse proxy</small></aside><main class="auth-main" id="content"><div class="auth-theme">${themeControl()}</div><div class="auth-card"><span class="auth-symbol">${icon("shield")}</span><h1>${setup.setup_required ? "Set up your gateway" : "Welcome back"}</h1><p class="muted">${setup.setup_required ? "Create the administrator account for your Aegis workspace." : "Sign in to manage certificates and proxy hosts."}</p><div id="message" aria-live="polite"></div><form id="auth-form">${setup.setup_required ? field("secret", "Bootstrap secret", "", "text", 'required autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false"') : ""}${field("username", "Username", "", "text", 'required minlength="3" maxlength="64" autocomplete="username"')}${field("password", "Password", "", "password", `required ${setup.setup_required ? 'minlength="14" maxlength="72" autocomplete="new-password"' : 'autocomplete="current-password"'}`)}${setup.setup_required ? "<small>Use a unique password of 14–72 bytes. Your bootstrap secret comes from deployment setup.</small>" : ""}<button class="primary auth-submit" type="submit" data-label="${setup.setup_required ? "Create administrator" : "Sign in"}">${setup.setup_required ? "Create administrator" : "Sign in"}${icon("arrow")}</button></form><div class="auth-footnote">${icon("key")}Your workspace. Your infrastructure.</div></div></main></div>`;
    formHandler("auth-form", async (f) => {
      if (setup.setup_required) {
        f.set("secret", String(f.get("secret") || "").trim());
        await api("/setup", "POST", Object.fromEntries(f));
        await start();
        notice("Administrator created. Sign in to get started.");
      } else {
        const me = await api<{ username: string; csrf: string }>(
          "/login",
          "POST",
          Object.fromEntries(f),
        );
        username = me.username;
        csrf = me.csrf;
        await refresh();
      }
    });
  } catch (error) {
    root.innerHTML = `<main id="content" class="auth-loading"><h1>Gateway unavailable</h1><div id="message"></div><p>Check the database connection, then try again.</p>${button("reconnect", "Retry connection", "secondary")}</main>`;
    notice(error instanceof Error ? error.message : "Connection failed.", true);
  }
}
const policyUI = makePolicyUI({
  api,
  sites: () => state.sites,
  openEditor,
  closeEditor,
  formHandler,
  refresh,
  notice,
});
const liveMapUI = makeLiveMap({ api, sites: () => state.sites, handleError });
const addressUI = makeAddressObjects({
  api,
  openEditor,
  closeEditor,
  formHandler,
  refresh,
  notice,
});
void start();
