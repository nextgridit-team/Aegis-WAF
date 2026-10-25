import type { State, Certificate, Account, DNSCredential, Job } from "./types";
import { APIError } from "./api-error";
import {esc,date,dateTime,icon,button,badge,field,check,actions,names,authority} from "./ui";
type Context = {
 state:()=>State;
 reloadState:()=>Promise<void>;
 currentPage:()=>string;
 handleError:(error:unknown)=>Promise<void>;
 api:<T>(path:string,method?:string,body?:unknown)=>Promise<T>;
 openEditor:(title:string,html:string,step?:number)=>void;
 closeEditor:()=>void;
 formHandler:(id:string,submit:(data:FormData)=>Promise<void>)=>void;
 refresh:()=>Promise<void>;
 notice:(message:string,error?:boolean)=>void;
 certStatus:(certificate:Certificate)=>string;
 newestJob:(id:number)=>Job|undefined;
};
export function makeCertificateForms(c:Context){
 const {api,openEditor,closeEditor,formHandler,refresh,notice,certStatus,newestJob}=c;
 let reviewedDirectory="",termsSerial=0;
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
function dnsCredentialForm(credential?: DNSCredential) {
  openEditor(
    credential ? "Edit Cloudflare credential" : "Connect Cloudflare",
    `<p class="form-intro">Use a Cloudflare API token with Zone Read and DNS Edit, scoped to the zones you want to manage.</p><form id="dns-form">${field("name", "Credential name", credential?.name || "", "text", 'required maxlength="120"')}${field("api_token", credential ? "New API token (leave blank to keep)" : "Cloudflare API token", "", "password", `autocomplete="new-password" ${credential ? "" : "required"}`)}<small>Stored encrypted for automatic renewal. Existing tokens are never displayed.</small>${actions("Save Cloudflare credential")}</form>`,
  );
  formHandler("dns-form", async (f) => {
    await api(
      "/dns/credentials" + (credential ? "/" + credential.id : ""),
      credential ? "PUT" : "POST",
      { name: f.get("name"), api_token: f.get("api_token") },
    );
    closeEditor();
    await refresh();
    notice("Cloudflare credential saved.");
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
    await c.reloadState();
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
async function loadTerms(formID = "account-form") {
  const form = document.getElementById(formID) as HTMLFormElement | null;
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
      await c.handleError(error);
    }
  } finally {
    if (serial === termsSerial) reload.disabled = false;
  }
}
function canonicalDirectory(value: string) {
  return value === "production"
    ? "https://acme-v02.api.letsencrypt.org/directory"
    : value === "staging"
      ? "https://acme-staging-v02.api.letsencrypt.org/directory"
      : value;
}
function issueForm(accountID?: number) {
  const selected = c.state().accounts.find((a) => a.id === accountID);
  const initialDirectory = selected
    ? selected.directory.includes("acme-staging-v02.api.letsencrypt.org")
      ? "staging"
      : selected.directory.includes("acme-v02.api.letsencrypt.org")
        ? "production"
        : "custom"
    : "production";
  const account =
    selected ||
    c.state().accounts.find(
      (a) => a.directory === canonicalDirectory(initialDirectory),
    );
  reviewedDirectory = "";
  openEditor(
    "Request a certificate",
    `<p class="form-intro">Enter your domains and Cloudflare access. Aegis handles verification, issuance and automatic renewal.</p><form id="issue-form">${field("domains", "Domains", "", "text", 'required placeholder="example.com, *.example.com"')}<small>Include the root domain separately if you also need a wildcard.</small>${field("email", "Account email", account?.email || c.state().accounts[0]?.email || "", "email", 'required autocomplete="email" placeholder="you@example.com"')}<small id="issue-authority-note"></small><small id="saved-account-note" hidden>Using your saved certificate authority account.</small><div id="cloudflare-verification"><div id="credential-picker" ${c.state().dns.length ? "" : "hidden"}><label class="field" for="dns-credential">Cloudflare credential</label><select id="dns-credential" name="dns_credential_id">${c.state().dns.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join("")}<option value="new">Use a new API token</option></select></div><div id="new-cloudflare-token">${field("api_token", "Cloudflare API token", "", "password", 'autocomplete="new-password"')}<small>Use a token scoped to your zone with Zone Read and DNS Edit. Saved encrypted for renewals.</small></div><small>No inbound port 80 is needed.</small></div><details class="advanced"><summary>Advanced options</summary><label class="field" for="directory">Certificate authority</label><select name="directory" id="directory"><option value="production">Let’s Encrypt · production</option><option value="staging">Let’s Encrypt · staging (testing)</option><option value="custom">Custom ACME server</option></select><div id="custom-directory" hidden>${field("custom", "Directory URL", selected && initialDirectory === "custom" ? selected.directory : "", "url", 'placeholder="https://ca.example.com/directory"')}</div><label class="field" for="challenge-type">Domain verification</label><select id="challenge-type" name="challenge_type"><option value="dns-01">DNS-01 · Cloudflare</option><option value="http-01">HTTP-01 · public port 80</option></select>${field("name", "Certificate name (optional)", "", "text", 'maxlength="120" placeholder="Uses your first domain"')}</details><div id="http-verification" class="info-panel compact-info" hidden><p>Point these domains to this gateway and forward public port 80.</p>${check("dns_ready", "My DNS and port 80 forwarding are ready.", false)}</div><div class="terms-box"><div id="ca-terms" aria-live="polite">Loading authority terms…</div>${button("review-terms", "Reload terms", "text-button")}${check("accept_terms", "I accept this authority’s terms of service.", false, "required disabled")}</div><div id="issue-progress" class="muted" aria-live="polite"></div>${actions("Request certificate")}</form>`,
  );
  const form = document.getElementById("issue-form") as HTMLFormElement;
  const isActive = () =>
    form.isConnected &&
    (form.closest("dialog") as HTMLDialogElement | null)?.open === true;
  const directory = form.elements.namedItem("directory") as HTMLSelectElement;
  const custom = form.elements.namedItem("custom") as HTMLInputElement;
  const email = form.elements.namedItem("email") as HTMLInputElement;
  const verification = form.elements.namedItem(
    "challenge_type",
  ) as HTMLSelectElement;
  const credential = form.elements.namedItem(
    "dns_credential_id",
  ) as HTMLSelectElement;
  const token = form.elements.namedItem("api_token") as HTMLInputElement;
  const progress = document.getElementById("issue-progress")!;
  const getDirectory = () =>
    directory.value === "custom" ? custom.value.trim() : directory.value;
  const showCredential = () => {
    const dns = verification.value === "dns-01";
    document.getElementById("cloudflare-verification")!.hidden = !dns;
    document.getElementById("new-cloudflare-token")!.hidden =
      credential.value !== "new";
    token.disabled = !dns || credential.value !== "new";
    token.required = !token.disabled;
    credential.disabled = !dns;
    document.getElementById("http-verification")!.hidden = dns;
    const ready = form.elements.namedItem("dns_ready") as HTMLInputElement;
    ready.disabled = dns;
    ready.required = !dns;
  };
  const updateAccount = () => {
    document.getElementById("issue-authority-note")!.textContent =
      directory.value === "production"
        ? "Let’s Encrypt · browser-trusted certificates."
        : directory.value === "staging"
          ? "Testing only: staging certificates are not trusted by browsers."
          : "Custom certificate authority.";
    const saved = c.state().accounts.find(
      (a) => a.directory === canonicalDirectory(getDirectory()),
    );
    email.readOnly = Boolean(saved);
    if (saved) email.value = saved.email;
    document.getElementById("saved-account-note")!.hidden = !saved;
  };
  const clearTerms = () => {
    termsSerial++;
    reviewedDirectory = "";
    const checkbox = form.elements.namedItem(
      "accept_terms",
    ) as HTMLInputElement;
    checkbox.checked = false;
    checkbox.disabled = true;
    form.querySelector<HTMLButtonElement>(
      '[data-action="review-terms"]',
    )!.disabled = false;
    document.getElementById("ca-terms")!.textContent =
      "Load and review this authority’s terms.";
  };
  directory.value = initialDirectory;
  if (!c.state().dns.length) credential.value = "new";
  directory.addEventListener("change", () => {
    clearTerms();
    document.getElementById("custom-directory")!.hidden =
      directory.value !== "custom";
    updateAccount();
    if (directory.value !== "custom") void loadTerms("issue-form");
  });
  custom.addEventListener("input", () => {
    clearTerms();
    updateAccount();
  });
  verification.addEventListener("change", showCredential);
  credential.addEventListener("change", showCredential);
  document.getElementById("custom-directory")!.hidden =
    directory.value !== "custom";
  updateAccount();
  showCredential();
  formHandler("issue-form", async (f) => {
    const dir = getDirectory();
    const canonical = canonicalDirectory(dir);
    const hosts = names(f.get("domains"));
    const dns = verification.value === "dns-01";
    const apiToken = token.value.trim();
    if (!hosts.length) throw new Error("Enter at least one domain.");
    if (!f.has("accept_terms") || reviewedDirectory !== dir)
      throw new Error(
        "Load and accept this certificate authority’s terms first.",
      );
    if (
      dns &&
      credential.value === "new" &&
      !/^[A-Za-z0-9_-]{20,256}$/.test(apiToken)
    )
      throw new Error("Paste a Cloudflare API token without a Bearer prefix.");
    if (!dns && hosts.some((h) => h.startsWith("*.")))
      throw new Error(
        "Wildcard certificates require Cloudflare DNS verification.",
      );
    try {
      let savedAccount = c.state().accounts.find((a) => a.directory === canonical);
      if (!savedAccount) {
        progress.textContent = "Registering with the certificate authority…";
        try {
          const result = await api<{ id: number }>("/acme/accounts", "POST", {
            directory: dir,
            email: email.value,
            accept_terms: true,
          });
          savedAccount = {
            id: result.id,
            directory: canonical,
            email: email.value,
            tos_accepted_at: new Date().toISOString(),
          };
          c.state().accounts.push(savedAccount);
        } catch (error) {
          // An ambiguous registration response may already have committed. Re-read
          // before allowing a retry to register the same account again.
          try {
            c.state().accounts = await api<Account[]>("/acme/accounts");
          } catch {
            /* Preserve the original error. */
          }
          savedAccount = c.state().accounts.find(
            (a) => a.directory === canonical && a.email === email.value,
          );
          if (!savedAccount) throw error;
        }
        if (!isActive()) return;
        updateAccount();
      }
      let credentialID =
        dns && credential.value !== "new"
          ? Number(credential.value)
          : undefined;
      if (dns && credential.value === "new") {
        progress.textContent =
          "Saving Cloudflare access for automatic renewal…";
        const name = ("Cloudflare: " + hosts[0]).slice(0, 120);
        const result = await api<{ id: number }>("/dns/credentials", "POST", {
          name,
          api_token: apiToken,
        });
        c.state().dns.push({ id: result.id, name, provider: "cloudflare" });
        if (!isActive()) return;
        credential.innerHTML =
          c.state().dns
            .map((d) => `<option value="${d.id}">${esc(d.name)}</option>`)
            .join("") + `<option value="new">Use a new API token</option>`;
        credential.value = String(result.id);
        credentialID = result.id;
        token.value = "";
        document.getElementById("credential-picker")!.hidden = false;
        showCredential();
      }
      progress.textContent = "Requesting your certificate…";
      await api("/acme/certificates", "POST", {
        name: String(f.get("name") || "").trim() || hosts[0].slice(0, 120),
        domains: hosts,
        account_id: savedAccount.id,
        challenge_type: verification.value,
        ...(dns ? { dns_credential_id: credentialID } : {}),
      });
      if (!isActive()) return;
      closeEditor();
      if (c.currentPage() !== "certificates") history.pushState(null, "", "#certificates");
      await refresh();
      notice(
        "Certificate requested. Verification and renewal are automatic; status updates below.",
      );
    } catch (error) {
      progress.textContent =
        "Your confirmed setup steps have been saved. Correct the error and retry.";
      throw error;
    }
  });
  void loadTerms("issue-form");
}
function certificateDetails(c: Certificate) {
  const job = newestJob(c.id);
  openEditor(
    c.name,
    `<div class="detail-status">${certStatus(c)}${badge(c.origin === "acme" ? "Automatic renewal" : "Uploaded PEM")}</div><dl class="details"><dt>Covered domains</dt><dd class="domain">${c.domains.map(esc).join("<br>")}</dd><dt>Issuer</dt><dd>${esc(c.issuer || "Waiting for issuance")}</dd><dt>Valid from</dt><dd>${esc(date(c.not_before))}</dd><dt>Expires</dt><dd>${esc(date(c.not_after))}</dd>${c.origin === "acme" ? `<dt>Verification</dt><dd>${c.challenge_type === "dns-01" ? "DNS-01 · Cloudflare" : "HTTP-01"}</dd>` : ""}<dt>Connected sites</dt><dd>${c.assigned_sites.map((s) => esc(s.name)).join(", ") || "Not connected yet"}</dd></dl>${c.pending_dns_cleanup && job?.status === "succeeded" ? `<div class="info-panel"><p>Challenge TXT cleanup is pending and will retry automatically. Check Cloudflare token permissions if it persists.</p></div>` : ""}${job ? `<details class="advanced"><summary>ACME details</summary><p>Attempt ${job.attempts} · ${esc(job.status)}</p>${job.error ? `<p class="error-text">${esc(job.error)}</p>` : ""}${job.orders.map((o) => `<small class="domain">${esc(o.status)} · ${esc(o.url)}</small>`).join("")}</details>` : ""}<div class="form-actions split-actions">${button("delete-cert", "Delete certificate", "danger", c.id)}<div>${c.origin === "upload" ? button("replace", "Replace PEM", "secondary", c.id) : ""}${c.validity === "valid" ? button("connect", `${icon("arrow")}Connect site`, "primary", c.id) : ""}${job?.status === "retry" ? button("retry", "Retry now", "primary", job.id) : ""}</div></div>`,
  );
}
return { uploadForm, dnsCredentialForm, accountForm, loadTerms, issueForm, certificateDetails };
}
