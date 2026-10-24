import { makePolicyUI } from "./policies";
export {};
type Site = {
  id: number;
  name: string;
  hostnames: string[];
  upstream: string;
  certificate_id: number | null;
  redirect_https: boolean;
  preserve_host: boolean;
  enabled: boolean;
};
type Certificate = {
  id: number;
  name: string;
  origin: string;
  domains: string[];
  issuer: string;
  not_before: string | null;
  not_after: string | null;
  validity: string;
  assigned_sites: { id: number; name: string }[];
};
type Account = {
  id: number;
  directory: string;
  email: string;
  tos_accepted_at: string;
};
type Job = {
  id: number;
  certificate_id: number;
  name: string;
  status: string;
  attempts: number;
  error: string;
  next_attempt: string;
  orders: { url: string; status: string; error: string }[];
};
type Gateway = {
  configuration_version: number;
  database_available: boolean;
  propagation_seconds: number;
  dropped_access_logs: number;
};
type Audit = {
  id: number;
  at: string;
  actor: string;
  action: string;
  resource: string;
};
type Access = {
  id: number;
  at: string;
  site_id: number;
  method: string;
  status: number;
  duration_ms: number;
  peer: string;
  rule_results: { rule_id: number; action: string; result: string }[];
};
type State = {
  sites: Site[];
  certs: Certificate[];
  accounts: Account[];
  jobs: Job[];
  gateway: Gateway;
};
const root = document.querySelector<HTMLDivElement>("#app")!;
let state: State = {
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
  reviewedDirectory = "",
  termsSerial = 0,
  returnFocus: HTMLElement | null = null;
const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const date = (v: string | null) =>
  v
    ? new Date(v).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : "Not issued yet";
const dateTime = (v: string) => new Date(v).toLocaleString();
const icons: Record<string, string> = {
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
const icon = (name: string) =>
  `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${icons[name] || icons.shield}"/></svg>`;
const button = (
  action: string,
  label: string,
  style = "primary",
  id?: number,
) =>
  `<button type="button" class="${style}" data-action="${action}" ${id ? `data-id="${id}"` : ""}>${label}</button>`;
const badge = (label: string, tone = "neutral") =>
  `<span class="badge ${tone}"><span class="badge-dot"></span>${esc(label)}</span>`;
const field = (
  name: string,
  label: string,
  value = "",
  type = "text",
  extra = "",
) =>
  `<label class="field">${label}<input name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;
const check = (name: string, label: string, checked = false, extra = "") =>
  `<label class="check"><input type="checkbox" name="${name}" ${checked ? "checked" : ""} ${extra}><span>${label}</span></label>`;
const actions = (label: string) =>
  `<div class="form-actions">${button("cancel", "Cancel", "secondary")}<button type="submit" class="primary" data-label="${label}">${label}${icon("arrow")}</button></div>`;
const names = (v: FormDataEntryValue | null) =>
  String(v || "")
    .split(/[\s,]+/)
    .filter(Boolean);
const authority = (a: Account) =>
  a.directory.includes("acme-staging-v02.api.letsencrypt.org")
    ? "Let’s Encrypt · staging"
    : a.directory.includes("acme-v02.api.letsencrypt.org")
      ? "Let’s Encrypt · production"
      : new URL(a.directory).host;
const newestJob = (id: number) =>
  state.jobs.find((j) => j.certificate_id === id);
class APIError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    signal: AbortSignal.timeout(
      path === "/acme/accounts" && method === "POST" ? 90000 : 20000,
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
  const [sites, certs, accounts, jobs, gateway] = await Promise.all([
    api<Site[]>("/sites"),
    api<Certificate[]>("/certificates"),
    api<Account[]>("/acme/accounts"),
    api<Job[]>("/acme/jobs"),
    api<Gateway>("/status"),
  ]);
  return { sites, certs, accounts, jobs, gateway };
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
    overview: "certificates",
    sites: "proxy-hosts",
    acme: "authorities",
  };
  const raw = location.hash.slice(1) || "certificates";
  return (
    aliases[raw] ||
    ([
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
    ["certificates", "certificate", "Certificates"],
    ["proxy-hosts", "globe", "Proxy hosts"],
    ["rules", "shield", "Rules"],
    ["traffic", "activity", "Traffic"],
    ["activity", "activity", "Activity"],
  ];
  root.innerHTML = `<div class="app-shell"><aside class="sidebar"><a class="brand" href="#certificates">${icon("shield")}<span>Aegis<span class="brand-suffix">WAF</span></span></a><div class="nav-label">WORKSPACE</div><nav aria-label="Main navigation">${nav.map(([id, i, label]) => `<a href="#${id}" ${page === id ? 'aria-current="page"' : ""}>${icon(i)}<span>${label}</span>${id === "certificates" && state.certs.length ? `<span class="nav-count" aria-hidden="true">${state.certs.length}</span>` : ""}</a>`).join("")}<div class="nav-divider"></div><a href="#authorities" ${page === "authorities" ? 'aria-current="page"' : ""}>${icon("key")}<span>Certificate authorities</span></a></nav><div class="sidebar-footer"><div class="avatar">${esc(username.slice(0, 1).toUpperCase())}</div><div><strong>${esc(username)}</strong><small>Administrator</small></div><button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icon("logout")}</button></div></aside><div class="workspace"><header class="topbar"><span>Workspace <span class="breadcrumb">/</span> <strong>${{ certificates: "Certificates", "proxy-hosts": "Proxy hosts", authorities: "Certificate authorities", activity: "Activity", rules: "Rules", traffic: "Traffic" }[page]}</strong></span><div id="connection" class="connection"><span></span>Gateway connected</div></header><main id="content"><div id="message" aria-live="polite"></div><div id="view"><div class="loading">Loading workspace…</div></div></main><footer class="workspace-footer"><span>Aegis WAF · Self-hosted application gateway</span><span>Certificate management & reverse proxy</span></footer></div></div><dialog id="editor" aria-labelledby="editor-title"></dialog>`;
  document.getElementById("editor")!.addEventListener("close", () => {
    if (returnFocus?.isConnected) returnFocus.focus();
  });
}
const heading = (title: string, text: string, buttons = "") =>
  `<div class="page-heading"><div><h1>${title}</h1><p>${text}</p></div><div class="heading-actions">${buttons}</div></div>`;
function table(headers: string[], rows: string[][], label: string) {
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(label)}"><table><thead><tr>${headers.map((h) => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
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
      `<span class="domain">${esc(s.upstream)}</span><small>${s.redirect_https ? "HTTP → HTTPS" : "HTTP allowed"} · ${s.preserve_host ? "Original host header" : "Upstream host header"}</small>`,
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
  document.title = `${({ certificates: "Certificates", "proxy-hosts": "Proxy hosts", authorities: "Certificate authorities", activity: "Activity", rules: "Rules", traffic: "Traffic" } as Record<string, string>)[page]} · Aegis WAF`;
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
      `<div class="info-panel"><h3>Start with staging</h3><p>Use Let’s Encrypt staging to check DNS and HTTP-01 reachability. Switch to production for certificates trusted by browsers.</p></div>`;
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
              ["Time", "Site / sender", "Request", "Rule outcomes", "Duration"],
              access.map((a) => [
                esc(dateTime(a.at)),
                `${a.site_id}<small>${esc(a.peer)}</small>`,
                `${esc(a.method)} · ${a.status}`,
                a.rule_results
                  ?.map(
                    (r) =>
                      `#${r.rule_id} · ${esc(r.action)} · ${esc(r.result)}`,
                  )
                  .join("<br>") || "—",
                `${a.duration_ms} ms`,
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
    page === "traffic"
  )
    return;
  polling = true;
  const stamp = epoch;
  try {
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
    if (signature !== lastSignature || page === "rules") {
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
function siteForm(site?: Site, certificate?: Certificate) {
  const c = site
    ? state.certs.find((c) => c.id === site.certificate_id)
    : certificate;
  openEditor(
    site ? "Edit proxy host" : "Connect an application",
    `<p class="form-intro">Choose the domain visitors will use and the address where your application runs.</p><form id="site-form">${field("name", "Name", site?.name || c?.name || "", "text", 'required maxlength="120" placeholder="My application"')}${field("hostnames", "Domains", site?.hostnames.join(", ") || c?.domains.filter((h) => !h.includes("*")).join(", ") || "", "text", 'required placeholder="app.example.com"')}<small>Separate multiple domains with commas.</small>${field("upstream", "Upstream URL", site?.upstream || "", "url", 'required placeholder="http://192.168.1.20:3000"')}<div class="form-divider"></div><label class="field" for="site-certificate">TLS certificate</label><select id="site-certificate" name="certificate_id"><option value="">HTTP only · no certificate</option>${state.certs
      .filter((v) => v.validity === "valid" || v.id === site?.certificate_id)
      .map(
        (v) =>
          `<option value="${v.id}" ${v.id === c?.id ? "selected" : ""}>${esc(v.name)} · ${esc(v.domains.join(", "))}${v.validity !== "valid" ? " (expired)" : ""}</option>`,
      )
      .join(
        "",
      )}</select>${check("redirect_https", "Redirect HTTP to HTTPS", site?.redirect_https ?? Boolean(c), c ? "" : "disabled")}<details class="advanced"><summary>Advanced settings</summary>${check("preserve_host", "Preserve the original Host header", site?.preserve_host ?? true)}${check("enabled", "Enable routing", site?.enabled ?? true)}</details>${actions("Save proxy host")}</form>`,
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
  formHandler("site-form", async (f) => {
    await api("/sites" + (site ? "/" + site.id : ""), site ? "PUT" : "POST", {
      name: f.get("name"),
      hostnames: names(f.get("hostnames")),
      upstream: f.get("upstream"),
      certificate_id: f.get("certificate_id")
        ? Number(f.get("certificate_id"))
        : null,
      redirect_https: f.has("redirect_https"),
      preserve_host: f.has("preserve_host"),
      enabled: f.has("enabled"),
    });
    closeEditor();
    await refresh();
    notice("Proxy host saved. Your gateway will apply it within 2 seconds.");
  });
}
function uploadForm(c?: Certificate) {
  openEditor(
    c ? "Replace certificate" : "Upload a PEM certificate",
    `<p class="form-intro">Add your certificate chain and matching private key. Keys are encrypted on the server and cannot be downloaded.</p><form id="upload-form">${field("name", "Certificate name", c?.name || "", "text", 'required maxlength="120"')}<label class="field">PEM certificate chain<textarea name="chain_pem" required spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label><small>Leaf certificate first, followed by intermediate certificates.</small><label class="field">PEM private key<textarea name="private_key_pem" required spellcheck="false" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>${actions(c ? "Replace certificate" : "Upload certificate")}</form>`,
  );
  formHandler("upload-form", async (f) => {
    await api(
      "/certificates" + (c ? "/" + c.id : ""),
      c ? "PUT" : "POST",
      Object.fromEntries(f),
    );
    closeEditor();
    await refresh();
    notice(
      "Certificate saved. TLS updates across your gateway within 2 seconds.",
    );
  });
}
function accountForm(continueToIssue = false) {
  reviewedDirectory = "";
  openEditor(
    "Connect a certificate authority",
    `<p class="form-intro">An ACME account lets Aegis request certificates and renew them automatically.</p><form id="account-form"><label class="field" for="directory">Certificate authority</label><select name="directory" id="directory"><option value="staging">Let’s Encrypt · staging (testing)</option><option value="production">Let’s Encrypt · production</option><option value="custom">Custom ACME server</option></select><div id="custom-directory" hidden>${field("custom", "Directory URL", "", "url", 'placeholder="https://ca.example.com/directory"')}</div>${field("email", "Account email", "", "email", 'required autocomplete="email" placeholder="you@example.com"')}<div class="terms-box"><div id="ca-terms" aria-live="polite">Loading authority terms…</div>${button("review-terms", "Reload terms", "text-button")}${check("accept_terms", "I accept this authority’s terms of service.", false, "required disabled")}</div><small>Staging certificates are for testing and won’t be trusted by browsers.</small>${actions(continueToIssue ? "Continue to domains" : "Connect authority")}</form>`,
    continueToIssue ? 1 : 0,
  );
  const directory = document.getElementById("directory") as HTMLSelectElement;
  directory.addEventListener("change", () => {
    termsSerial++;
    document.querySelector<HTMLButtonElement>(
      '[data-action="review-terms"]',
    )!.disabled = false;
    document.getElementById("custom-directory")!.hidden =
      directory.value !== "custom";
    reviewedDirectory = "";
    const checkbox = document.querySelector<HTMLInputElement>(
      "[name=accept_terms]",
    )!;
    checkbox.checked = false;
    checkbox.disabled = true;
    document.getElementById("ca-terms")!.textContent =
      directory.value === "custom"
        ? "Enter your directory URL, then load its terms."
        : "Loading authority terms…";
    if (directory.value !== "custom") void loadTerms();
  });
  document.querySelector("[name=custom]")!.addEventListener("input", () => {
    termsSerial++;
    document.querySelector<HTMLButtonElement>(
      '[data-action="review-terms"]',
    )!.disabled = false;
    reviewedDirectory = "";
    const checkbox = document.querySelector<HTMLInputElement>(
      "[name=accept_terms]",
    )!;
    checkbox.checked = false;
    checkbox.disabled = true;
  });
  formHandler("account-form", async (f) => {
    const dir =
      directory.value === "custom" ? String(f.get("custom")) : directory.value;
    if (!f.has("accept_terms") || reviewedDirectory !== dir)
      throw new Error(
        "Load and accept the terms for this certificate authority first.",
      );
    const account = await api<{ id: number }>("/acme/accounts", "POST", {
      directory: dir,
      email: f.get("email"),
      accept_terms: true,
    });
    state = await fetchState();
    if (continueToIssue) issueForm(account.id);
    else {
      closeEditor();
      await refresh();
      notice(
        "Certificate authority connected. You can now request a certificate.",
      );
    }
  });
  void loadTerms();
}
async function loadTerms() {
  const form = document.getElementById(
    "account-form",
  ) as HTMLFormElement | null;
  if (!form) return;
  const serial = ++termsSerial;
  const data = new FormData(form);
  const directory = String(
    data.get("directory") === "custom"
      ? data.get("custom")
      : data.get("directory"),
  );
  const target = document.getElementById("ca-terms")!;
  const checkbox = form.querySelector<HTMLInputElement>("[name=accept_terms]")!;
  const reload = form.querySelector<HTMLButtonElement>(
    "[data-action=review-terms]",
  )!;
  reviewedDirectory = "";
  checkbox.disabled = true;
  checkbox.checked = false;
  reload.disabled = true;
  target.textContent = "Loading authority terms…";
  try {
    const result = await api<{ terms_url: string }>(
      "/acme/directory?url=" + encodeURIComponent(directory),
    );
    const current = new FormData(form);
    const currentDirectory = String(
      current.get("directory") === "custom"
        ? current.get("custom")
        : current.get("directory"),
    );
    if (
      !form.isConnected ||
      currentDirectory !== directory ||
      serial !== termsSerial
    )
      return;
    const plainTerms = result.terms_url.match(
      /^data:text\/plain(?:;charset=utf-8)?,(.*)$/is,
    );
    if (plainTerms) {
      const text = decodeURIComponent(plainTerms[1]);
      if (text.length > 20000)
        throw new Error(
          "The authority's inline terms are too long to display.",
        );
      target.innerHTML = `<div class="inline-terms">${esc(text)}</div>`;
    } else {
      const u = result.terms_url ? new URL(result.terms_url) : null;
      if (u && u.protocol !== "https:")
        throw new Error("The authority returned an unsupported terms URL.");
      target.innerHTML = u
        ? `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">Read the authority’s terms of service ↗</a>`
        : "This authority does not publish a terms-of-service link.";
    }
    reviewedDirectory = directory;
    checkbox.disabled = false;
  } catch (error) {
    if (form.isConnected && serial === termsSerial) {
      target.textContent =
        "Could not load the terms. Check the directory URL and try again.";
      await handleError(error);
    }
  } finally {
    if (serial === termsSerial) reload.disabled = false;
  }
}
function issueForm(accountID?: number) {
  if (!state.accounts.length) {
    accountForm(true);
    return;
  }
  const account =
    state.accounts.find((a) => a.id === accountID) || state.accounts[0];
  openEditor(
    "Request a certificate",
    `<p class="form-intro">Tell Aegis which domains to secure. Your certificate will renew automatically after issuance.</p><form id="issue-form"><label class="field" for="issue-account">Certificate authority</label><select id="issue-account" name="account_id">${state.accounts.map((a) => `<option value="${a.id}" ${a.id === account.id ? "selected" : ""}>${esc(authority(a))} · ${esc(a.email)}</option>`).join("")}</select>${field("domains", "Domains", "", "text", 'required placeholder="app.example.com, www.example.com"')}<small>Use exact domain names. HTTP-01 does not support wildcards.</small>${field("name", "Certificate name (optional)", "", "text", 'maxlength="120" placeholder="Uses your first domain"')}<div class="info-panel compact-info"><h3>Before you request</h3><p>Point each domain’s DNS to this gateway and forward public port 80 to its HTTP listener. An existing proxy host isn’t required.</p>${check("dns_ready", "My DNS and port 80 forwarding are ready.", false, "required")}</div>${actions("Request certificate")}</form>`,
    2,
  );
  formHandler("issue-form", async (f) => {
    const hosts = names(f.get("domains"));
    await api("/acme/certificates", "POST", {
      name: String(f.get("name") || "").trim() || hosts[0],
      domains: hosts,
      account_id: Number(f.get("account_id")),
    });
    closeEditor();
    if (page !== "certificates") history.pushState(null, "", "#certificates");
    await refresh();
    notice(
      "Certificate requested. Issuance progress will update automatically below.",
    );
  });
}
function certificateDetails(c: Certificate) {
  const job = newestJob(c.id);
  openEditor(
    c.name,
    `<div class="detail-status">${certStatus(c)}${badge(c.origin === "acme" ? "Automatic renewal" : "Uploaded PEM")}</div><dl class="details"><dt>Covered domains</dt><dd class="domain">${c.domains.map(esc).join("<br>")}</dd><dt>Issuer</dt><dd>${esc(c.issuer || "Waiting for issuance")}</dd><dt>Valid from</dt><dd>${esc(date(c.not_before))}</dd><dt>Expires</dt><dd>${esc(date(c.not_after))}</dd><dt>Connected sites</dt><dd>${c.assigned_sites.map((s) => esc(s.name)).join(", ") || "Not connected yet"}</dd></dl>${job ? `<details class="advanced"><summary>ACME details</summary><p>Attempt ${job.attempts} · ${esc(job.status)}</p>${job.error ? `<p class="error-text">${esc(job.error)}</p>` : ""}${job.orders.map((o) => `<small class="domain">${esc(o.status)} · ${esc(o.url)}</small>`).join("")}</details>` : ""}<div class="form-actions split-actions">${button("delete-cert", "Delete certificate", "danger", c.id)}<div>${c.origin === "upload" ? button("replace", "Replace PEM", "secondary", c.id) : ""}${c.validity === "valid" ? button("connect", `${icon("arrow")}Connect site`, "primary", c.id) : ""}${job?.status === "retry" ? button("retry", "Retry now", "primary", job.id) : ""}</div></div>`,
  );
}
root.addEventListener("click", async (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>(
    "button[data-action]",
  );
  if (!b) return;
  const action = b.dataset.action,
    id = Number(b.dataset.id);
  try {
    if (await policyUI.handleAction(action, id, b.dataset.id)) return;
    switch (action) {
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
        await loadTerms();
        break;
      case "new-site":
        siteForm();
        break;
      case "edit-site":
        siteForm(state.sites.find((s) => s.id === id));
        break;
      case "connect": {
        const c = state.certs.find((c) => c.id === id);
        if (page !== "proxy-hosts") {
          closeEditor();
          history.pushState(null, "", "#proxy-hosts");
          await refresh();
        }
        siteForm(undefined, c);
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
    root.innerHTML = `<div class="auth-shell"><aside class="auth-story"><a href="#certificates" class="brand">${icon("shield")}<span>Aegis<span class="brand-suffix">WAF</span></span></a><div><div class="eyebrow">YOUR APPLICATIONS. YOUR EDGE.</div><h2>A secure home for<br>every application.</h2><p>Manage your certificates.<br>Connect your domains.<br>Keep your infrastructure yours.</p></div><small>Self-hosted · Certificate management & reverse proxy</small></aside><main class="auth-main" id="content"><div class="auth-card"><span class="auth-symbol">${icon("shield")}</span><h1>${setup.setup_required ? "Set up your gateway" : "Welcome back"}</h1><p class="muted">${setup.setup_required ? "Create the administrator account for your Aegis workspace." : "Sign in to manage certificates and proxy hosts."}</p><div id="message" aria-live="polite"></div><form id="auth-form">${setup.setup_required ? field("secret", "Bootstrap secret", "", "password", 'required autocomplete="off"') : ""}${field("username", "Username", "", "text", 'required minlength="3" maxlength="64" autocomplete="username"')}${field("password", "Password", "", "password", `required ${setup.setup_required ? 'minlength="14" maxlength="72" autocomplete="new-password"' : 'autocomplete="current-password"'}`)}${setup.setup_required ? "<small>Use a unique password of 14–72 bytes. Your bootstrap secret comes from deployment setup.</small>" : ""}<button class="primary auth-submit" type="submit" data-label="${setup.setup_required ? "Create administrator" : "Sign in"}">${setup.setup_required ? "Create administrator" : "Sign in"}${icon("arrow")}</button></form><div class="auth-footnote">${icon("key")}Your workspace. Your infrastructure.</div></div></main></div>`;
    formHandler("auth-form", async (f) => {
      if (setup.setup_required) {
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
void start();
