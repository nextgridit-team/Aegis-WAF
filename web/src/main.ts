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
type Status = {
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
};
const root = document.querySelector<HTMLDivElement>("#app")!;
let csrf = "",
  username = "",
  page = "overview",
  sites: Site[] = [],
  certs: Certificate[] = [],
  accounts: Account[] = [],
  jobs: Job[] = [],
  status: Status;
const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const date = (v: string | null) => (v ? new Date(v).toLocaleString() : "—");
const badge = (v: string) =>
  `<span class="badge ${["retry", "expired", "failed"].includes(v) ? "error" : ["pending", "queued", "running", "not yet valid"].includes(v) ? "warn" : ""}">${esc(v)}</span>`;
async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "aegis-waf",
      "X-CSRF-Token": csrf,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    if (res.status === 401 && username) {
      username = "";
      void start();
    }
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}
function notice(message: string, error = false) {
  const el = document.getElementById("message");
  if (el) {
    el.innerHTML = `<div class="notice ${error ? "error" : ""}" role="${error ? "alert" : "status"}">${esc(message)}</div>`;
    el.scrollIntoView({ block: "nearest" });
  }
}
function formHandler(id: string, submit: (f: FormData) => Promise<void>) {
  const form = document.getElementById(id) as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector<HTMLButtonElement>("button[type=submit]")!;
    btn.disabled = true;
    btn.textContent = "Working…";
    const label = btn.dataset.label || "Save";
    try {
      await submit(new FormData(form));
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  });
}
const field = (
  name: string,
  label: string,
  value = "",
  type = "text",
  extra = "",
) =>
  `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;
const check = (name: string, label: string, checked = false) =>
  `<label><input type="checkbox" name="${name}" ${checked ? "checked" : ""}>${label}</label>`;
const actions = (label = "Save") =>
  `<div class="actions"><button type="button" class="secondary" data-action="cancel">Cancel</button><button type="submit" data-label="${label}">${label}</button></div>`;
const names = (v: FormDataEntryValue | null) =>
  String(v || "")
    .split(/[\s,]+/)
    .filter(Boolean);
function empty(title: string, text: string) {
  return `<div class="empty"><h2>${title}</h2><p>${text}</p></div>`;
}
function shell() {
  const nav = [
    ["overview", "Overview"],
    ["sites", "Protected sites"],
    ["certificates", "Certificates"],
    ["acme", "ACME & renewal"],
    ["activity", "Activity"],
  ];
  root.innerHTML = `<header><div class="brand"><b>A</b>Aegis WAF <span class="inline-status">/ gateway console</span></div><div class="tools"><span class="inline-status">${esc(username)}</span><button class="secondary" data-action="logout">Sign out</button></div></header><div class="layout"><nav aria-label="Main navigation"><div class="section-label">Gateway operations</div>${nav.map(([id, label]) => `<a href="#${id}" ${page === id ? 'aria-current="page"' : ""}>${label}</a>`).join("")}<div class="footnote">Foundation · v0.1<br>Certificate management<br>and application routing</div></nav><main id="content"><div id="message" aria-live="polite"></div><div id="view" class="loading">Loading gateway state…</div></main></div>`;
}
function heading(eyebrow: string, title: string, text: string, buttons = "") {
  return `<div class="heading"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p>${text}</p></div>${buttons ? `<div class="toolbar">${buttons}</div>` : ""}</div>`;
}
function table(headers: string[], rows: string[][]) {
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(headers.join(", "))}"><table><thead><tr>${headers.map((h) => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
async function refresh() {
  page = location.hash.slice(1) || "overview";
  if (!["overview", "sites", "certificates", "acme", "activity"].includes(page))
    page = "overview";
  shell();
  try {
    [sites, certs, accounts, jobs, status] = await Promise.all([
      api<Site[]>("/sites"),
      api<Certificate[]>("/certificates"),
      api<Account[]>("/acme/accounts"),
      api<Job[]>("/acme/jobs"),
      api<Status>("/status"),
    ]);
    await render();
  } catch (e) {
    notice((e as Error).message, true);
    document.getElementById("view")!.innerHTML =
      '<p>Gateway state could not be loaded. <button data-action="refresh" class="secondary">Try again</button></p>';
  }
}
async function render() {
  const view = document.getElementById("view")!;
  view.className = "";
  const refreshBtn =
    '<button class="secondary" data-action="refresh">Refresh</button>';
  if (page === "overview") {
    const active = sites.filter((s) => s.enabled).length,
      valid = certs.filter((c) => c.validity === "valid").length;
    view.innerHTML =
      heading(
        "Certificate & proxy foundation",
        "Your application edge",
        "Manage TLS and route traffic to your applications. Configuration is shared by every replica.",
        refreshBtn,
      ) +
      (!status.database_available
        ? '<div class="notice error">Database connectivity is degraded. Loaded replicas continue serving their last configuration.</div>'
        : "") +
      `<div class="grid"><div class="stat"><span>Enabled sites</span><strong>${active}</strong><span>${sites.length} configured</span></div><div class="stat"><span>Valid certificates</span><strong>${valid}</strong><span>${certs.length} total</span></div><div class="stat"><span>Configuration</span><strong>v${status.configuration_version}</strong><span>${status.propagation_seconds}s propagation</span></div></div><div class="split"><section class="panel"><div class="eyebrow">Bring an application online</div><h2>Start with its certificate</h2><p class="muted">Upload a certificate chain and key, or use HTTP-01 to request a certificate from your ACME authority. Then attach it to a protected site.</p><div class="toolbar"><a href="#certificates">Manage certificates →</a><a href="#sites">Configure sites →</a></div></section><section class="panel"><h2>Replica status</h2><dl class="details"><dt>Database</dt><dd>${badge(status.database_available ? "connected" : "unavailable")}</dd><dt>Snapshot version</dt><dd class="mono">${status.configuration_version}</dd><dt>Access log drops</dt><dd>${status.dropped_access_logs}</dd><dt>Active scope</dt><dd>TLS termination & reverse proxy</dd></dl><small>Status describes the replica serving this request. AI and traffic detection are not enabled in this milestone.</small></section></div>`;
  }
  if (page === "sites") {
    view.innerHTML =
      heading(
        "Application routing",
        "Protected sites",
        "Exact hostnames select an upstream. Upstream HTTPS certificates are verified.",
        `<button data-action="new-site">Add site</button>`,
      ) +
      `<div id="editor"></div>` +
      (sites.length
        ? table(
            ["Application", "Upstream", "TLS certificate", "State", "Manage"],
            sites.map((s) => [
              `${esc(s.name)}<small class="mono">${s.hostnames.map(esc).join("<br>")}</small>`,
              `<span class="mono">${esc(s.upstream)}</span><small>${s.preserve_host ? "Preserve original Host" : "Use upstream Host"} · ${s.redirect_https ? "Redirect HTTP to HTTPS" : "Allow HTTP"}</small>`,
              esc(
                certs.find((c) => c.id === s.certificate_id)?.name ||
                  "HTTP only",
              ),
              badge(s.enabled ? "enabled" : "disabled"),
              `<div class="toolbar"><button class="secondary" data-action="edit-site" data-id="${s.id}">Edit</button><button class="danger" data-action="delete-site" data-id="${s.id}">Delete</button></div>`,
            ]),
          )
        : empty(
            "No sites configured",
            "Add an application hostname and its upstream to begin routing traffic.",
          ));
  }
  if (page === "certificates") {
    view.innerHTML =
      heading(
        "TLS inventory",
        "Certificates",
        "Private keys are encrypted in PostgreSQL and are never returned by this console.",
        `<button data-action="upload">Upload certificate</button>`,
      ) +
      `<div id="editor"></div>` +
      (certs.length
        ? table(
            ["Certificate", "Issuer & validity", "Assigned sites", "Manage"],
            certs.map((c) => [
              `${esc(c.name)} <small>${badge(c.origin === "acme" ? "ACME-managed" : "uploaded")} #${c.id}</small><small class="mono">${c.domains.map(esc).join("<br>")}</small>`,
              `${badge(c.validity)}<small>${esc(c.issuer || "Awaiting issuance")}</small><small>From ${esc(date(c.not_before))}<br>Expires ${esc(date(c.not_after))}</small>`,
              c.assigned_sites.map((s) => esc(s.name)).join("<br>") ||
                '<span class="muted">Unassigned</span>',
              `<div class="toolbar">${c.origin === "upload" ? `<button class="secondary" data-action="replace" data-id="${c.id}">Replace</button>` : ""}<button class="danger" data-action="delete-cert" data-id="${c.id}">Delete</button></div>`,
            ]),
          )
        : empty(
            "Your TLS inventory is empty",
            "Upload an existing certificate, or open ACME & renewal to request one.",
          ));
  }
  if (page === "acme") {
    view.innerHTML =
      heading(
        "Certificate automation",
        "ACME & renewal",
        "HTTP-01 requires public port 80 to reach every replica. Renewal starts 30 days before expiration.",
        `<button class="secondary" data-action="new-account">Register account</button><button data-action="issue">Request certificate</button>`,
      ) +
      `<div id="editor"></div><h2>Registered authorities</h2>` +
      (accounts.length
        ? table(
            ["Account", "Directory", "Terms accepted"],
            accounts.map((a) => [
              `#${a.id} · ${esc(a.email)}`,
              `<span class="mono">${esc(a.directory)}</span>`,
              esc(date(a.tos_accepted_at)),
            ]),
          )
        : empty(
            "No ACME account",
            "Register an account and accept the certificate authority’s terms first.",
          )) +
      `<div class="toolbar"><h2>Issuance & renewal jobs</h2>${refreshBtn}</div>` +
      (jobs.length
        ? table(
            ["Certificate / job", "Status", "Attempts & next run", "Details"],
            jobs.map((j) => [
              `${esc(j.name)}<small>#${j.id} · certificate #${j.certificate_id}</small>`,
              badge(j.status),
              `${j.attempts}<small>${j.status === "succeeded" ? "Complete" : esc(date(j.next_attempt))}</small>`,
              `${j.error ? `<p>${esc(j.error)}</p>` : ""}${j.orders.map((o) => `<small>${badge(o.status)} <span class="mono">${esc(o.url)}</span></small>`).join("")}${j.status === "retry" ? `<button class="secondary" data-action="retry" data-id="${j.id}">Retry now</button>` : ""}`,
            ]),
          )
        : empty(
            "No issuance jobs",
            "Requested certificates and automatic renewals appear here.",
          ));
  }
  if (page === "activity") {
    const [audit, access] = await Promise.all([
      api<Audit[]>("/audit"),
      api<Access[]>("/access-logs"),
    ]);
    view.innerHTML =
      heading(
        "Operational history",
        "Activity",
        "The latest 200 audit events and access records. Request bodies, query strings, and keys are excluded.",
        refreshBtn,
      ) +
      `<h2>Administrative audit</h2>` +
      (audit.length
        ? table(
            ["Time", "Actor", "Action", "Resource"],
            audit.map((a) => [
              esc(date(a.at)),
              esc(a.actor),
              `<span class="mono">${esc(a.action)}</span>`,
              esc(a.resource),
            ]),
          )
        : empty(
            "No audit events",
            "Security-relevant administrative actions appear here.",
          )) +
      "<h2>Application access</h2>" +
      (access.length
        ? table(
            ["Time", "Site / sender", "Method / status", "Duration"],
            access.map((a) => [
              esc(date(a.at)),
              `${a.site_id}<small class="mono">${esc(a.peer)}</small>`,
              `${esc(a.method)} · ${a.status}`,
              `${a.duration_ms} ms`,
            ]),
          )
        : empty(
            "No access records",
            "Records appear after requests reach a configured site.",
          ));
  }
}
function editor(html: string) {
  const el = document.getElementById("editor")!;
  el.innerHTML = `<section class="panel form-panel">${html}</section>`;
  el.scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto"
      : "smooth",
    block: "start",
  });
  el.querySelector<HTMLElement>("input,select,textarea")?.focus();
}
function siteForm(s?: Site) {
  editor(
    `<h2>${s ? "Edit site" : "Add protected site"}</h2><form id="site-form">${field("name", "Application name", s?.name || "", "text", 'required maxlength="120"')}${field("hostnames", "Hostnames", s?.hostnames.join(", ") || "", "text", 'required placeholder="app.example.com, www.example.com"')}<small>Comma-separated exact DNS hostnames. Wildcard routing is not enabled.</small>${field("upstream", "Upstream URL", s?.upstream || "", "url", 'required placeholder="http://service:3000"')}<label>TLS certificate<select name="certificate_id" aria-label="TLS certificate"><option value="">HTTP only</option>${certs
      .filter((c) => c.validity === "valid")
      .map(
        (c) =>
          `<option value="${c.id}" ${c.id === s?.certificate_id ? "selected" : ""}>${esc(c.name)} · ${esc(c.domains.join(", "))}</option>`,
      )
      .join(
        "",
      )}</select></label>${check("redirect_https", "Redirect HTTP to HTTPS", s?.redirect_https ?? false)}${check("preserve_host", "Preserve the original Host header", s?.preserve_host ?? true)}${check("enabled", "Enable routing", s?.enabled ?? true)}${actions("Save site")}</form>`,
  );
  formHandler("site-form", async (f) => {
    await api("/sites" + (s ? "/" + s.id : ""), s ? "PUT" : "POST", {
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
    await refresh();
    notice("Site saved. Replicas apply this configuration within 2 seconds.");
  });
}
function uploadForm(c?: Certificate) {
  editor(
    `<h2>${c ? "Replace certificate" : "Upload certificate"}</h2><p class="muted">Paste the leaf certificate followed by intermediate certificates, and an unencrypted PEM private key. The chain must be currently valid.</p><form id="upload-form">${field("name", "Certificate name", c?.name || "", "text", 'required maxlength="120"')}<label>PEM certificate chain<textarea name="chain_pem" required spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label><label>PEM private key<textarea name="private_key_pem" required spellcheck="false" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label><small>PKCS#8, RSA PKCS#1, or EC SEC1. A replacement must cover every assigned hostname.</small>${actions(c ? "Replace certificate" : "Upload certificate")}</form>`,
  );
  formHandler("upload-form", async (f) => {
    await api(
      "/certificates" + (c ? "/" + c.id : ""),
      c ? "PUT" : "POST",
      Object.fromEntries(f),
    );
    await refresh();
    notice("Certificate saved. TLS updates on every replica within 2 seconds.");
  });
}
function accountForm() {
  editor(
    `<h2>Register an ACME account</h2><form id="account-form"><label>Certificate authority<select name="directory" id="directory" aria-label="Certificate authority"><option value="staging">Let’s Encrypt · staging (test certificates)</option><option value="production">Let’s Encrypt · production</option><option value="custom">Custom ACME directory</option></select></label>${field("custom", "Custom directory URL (when selected)", "", "url", 'placeholder="https://ca.example.com/directory"')}${field("email", "Account email", "", "email", 'required autocomplete="email"')}<button class="secondary" type="button" data-action="review-terms">Load CA terms</button><div id="ca-terms"></div>${check("accept_terms", "I have read and accept this certificate authority’s terms of service.")}<small>Acceptance is recorded with the account. Staging certificates are not trusted by browsers.</small>${actions("Register account")}</form>`,
  );
  formHandler("account-form", async (f) => {
    if (!f.has("accept_terms"))
      throw new Error("Explicit acceptance of the CA terms is required.");
    const directory =
      f.get("directory") === "custom"
        ? String(f.get("custom"))
        : String(f.get("directory"));
    if (directory !== reviewedDirectory)
      throw new Error(
        "Load and review the terms for the selected CA before registering.",
      );
    await api("/acme/accounts", "POST", {
      directory,
      email: f.get("email"),
      accept_terms: true,
    });
    await refresh();
    notice("ACME account registered.");
  });
}
let reviewedDirectory = "";
function issueForm() {
  if (!accounts.length) {
    notice("Register an ACME account first.", true);
    return;
  }
  editor(
    `<h2>Request an HTTP-01 certificate</h2><p class="muted">Point each hostname’s public DNS to this gateway and forward public port 80 to HTTP port 8080. Challenges are shared through PostgreSQL.</p><form id="issue-form">${field("name", "Certificate name", "", "text", 'required maxlength="120"')}${field("domains", "Hostnames", "", "text", 'required placeholder="app.example.com, www.example.com"')}<label>ACME account<select name="account_id" aria-label="ACME account">${accounts.map((a) => `<option value="${a.id}">${esc(a.email)} · ${esc(a.directory)}</option>`).join("")}</select></label>${actions("Queue issuance")}</form>`,
  );
  formHandler("issue-form", async (f) => {
    await api("/acme/certificates", "POST", {
      name: f.get("name"),
      domains: names(f.get("domains")),
      account_id: Number(f.get("account_id")),
    });
    await refresh();
    notice(
      "Issuance queued. Refresh job status to follow progress; attach the certificate after issuance completes.",
    );
  });
}
root.addEventListener("click", async (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(
    "button[data-action]",
  );
  if (!btn) return;
  const id = Number(btn.dataset.id);
  try {
    switch (btn.dataset.action) {
      case "refresh":
        await refresh();
        break;
      case "cancel":
        document.getElementById("editor")!.innerHTML = "";
        break;
      case "logout":
        await api("/logout", "POST", {});
        username = "";
        csrf = "";
        await start();
        break;
      case "new-site":
        siteForm();
        break;
      case "edit-site":
        siteForm(sites.find((s) => s.id === id));
        break;
      case "upload":
        uploadForm();
        break;
      case "replace":
        uploadForm(certs.find((c) => c.id === id));
        break;
      case "new-account":
        reviewedDirectory = "";
        accountForm();
        break;
      case "issue":
        issueForm();
        break;
      case "delete-site":
      case "delete-cert":
        if (
          confirm(
            `Delete this ${btn.dataset.action === "delete-site" ? "site and stop its routing" : "certificate"}?`,
          )
        ) {
          await api(
            `/${btn.dataset.action === "delete-site" ? "sites" : "certificates"}/${id}`,
            "DELETE",
          );
          await refresh();
          notice("Deleted. Replicas update within 2 seconds.");
        }
        break;
      case "retry":
        btn.disabled = true;
        await api(`/acme/jobs/${id}/retry`, "POST", {});
        await refresh();
        notice("Retry queued.");
        break;
      case "review-terms": {
        const f = new FormData(
          document.getElementById("account-form") as HTMLFormElement,
        );
        const directory = String(
          f.get("directory") === "custom"
            ? f.get("custom")
            : f.get("directory"),
        );
        btn.disabled = true;
        const terms = await api<{ terms_url: string }>(
          `/acme/directory?url=${encodeURIComponent(directory)}`,
        );
        const u = terms.terms_url ? new URL(terms.terms_url) : null;
        if (u && u.protocol !== "https:")
          throw new Error("The CA returned a non-HTTPS terms URL.");
        document.getElementById("ca-terms")!.innerHTML = u
          ? `<p><a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">Read this CA’s terms of service ↗</a></p>`
          : "<p>This CA did not advertise a terms-of-service URL.</p>";
        reviewedDirectory = directory;
        break;
      }
    }
  } catch (e) {
    notice((e as Error).message, true);
  } finally {
    btn.disabled = false;
  }
});
window.addEventListener("hashchange", () => {
  if (username) void refresh();
});
async function start() {
  root.innerHTML = '<div class="loading">Connecting to management…</div>';
  try {
    const setup = await api<{ setup_required: boolean }>("/setup");
    try {
      const me = await api<{ username: string; csrf: string }>("/me");
      username = me.username;
      csrf = me.csrf;
      await refresh();
      return;
    } catch (e) {
      if (!(e as Error).message.match(/authentication|expired/)) throw e;
    }
    root.innerHTML = `<main class="auth" id="content"><div class="brand"><b>A</b>Aegis WAF</div><div class="eyebrow">Private gateway console</div><h1>${setup.setup_required ? "Create your administrator" : "Sign in to your gateway"}</h1><p class="muted">${setup.setup_required ? "Use your deployment bootstrap secret to establish the first administrator. Setup is available only once." : "Manage protected sites, certificates, and renewal operations."}</p><div id="message" aria-live="polite"></div><form id="auth-form">${setup.setup_required ? field("secret", "Bootstrap secret", "", "password", 'required autocomplete="off"') : ""}${field("username", "Username", "", "text", 'required minlength="3" maxlength="64" autocomplete="username"')}${field("password", "Password", "", "password", `required ${setup.setup_required ? 'minlength="14" maxlength="72" autocomplete="new-password"' : 'autocomplete="current-password"'}`)}${setup.setup_required ? "<small>Choose a unique password of 14–72 bytes. There are no default credentials.</small>" : ""}<button type="submit" data-label="${setup.setup_required ? "Create administrator" : "Sign in"}">${setup.setup_required ? "Create administrator" : "Sign in"}</button></form><small>Use an HTTPS management endpoint or a localhost tunnel.</small></main>`;
    formHandler("auth-form", async (f) => {
      if (setup.setup_required) {
        await api("/setup", "POST", Object.fromEntries(f));
        await start();
        notice("Administrator created. Sign in to continue.");
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
  } catch (e) {
    root.innerHTML = `<main class="auth" id="content"><h1>Gateway unavailable</h1><p role="alert">${esc((e as Error).message)}</p><p>The management database must be available before setup or sign-in.</p><button data-action="reconnect">Retry connection</button></main>`;
    root
      .querySelector("[data-action=reconnect]")
      ?.addEventListener("click", () => void start());
  }
}
void start();
