import { esc } from "./ui";
export type UpstreamTLS = {
  server_name?: string;
  trusted_certificates_pem?: string;
};
type PeerCertificate = {
  pem: string;
  sha256: string;
  subject: string;
  issuer: string;
  not_after: string;
  can_trust: boolean;
};
export function upstreamCheckMarkup(tls?: UpstreamTLS) {
  return `<div class="upstream-check"><button type="button" class="secondary compact" data-test-upstream>Test upstream</button><p data-upstream-test-result role="status" aria-live="polite"></p><div data-upstream-certificate hidden class="info-panel"></div><label class="check"><input name="upstream_trust_enabled" type="checkbox" ${tls?.trusted_certificates_pem ? "checked" : ""}><span>Trust a private upstream certificate</span></label><small data-upstream-trust-hint>For a private or self-signed backend, test first to display its certificate, or import its CA under Upstream TLS. Trust is scoped to this host; name and validity checks remain active.</small></div><details class="advanced"><summary>Upstream TLS</summary><p class="muted">Aegis verifies HTTPS backends separately from the certificate visitors see.</p><label class="field">Upstream TLS server name<input name="upstream_tls_name" value="${esc(tls?.server_name || "")}" maxlength="253" placeholder="Optional: backend.internal.example"></label><small>Use a name covered by the backend certificate when connecting to an IP. This changes TLS verification/SNI; it does not change the HTTP Host header.</small><label class="field">Trusted upstream certificates (PEM)<textarea name="upstream_trusted_certificates" rows="5" maxlength="65536" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${esc(tls?.trusted_certificates_pem || "")}</textarea></label><small>Prefer the private CA certificate for automatic backend renewals. Trusting the displayed server certificate pins it and requires updating it when it rotates. Public certificates only; never paste a private key. Check Trust a private upstream certificate to use these certificates. Test checks unsaved values; Save applies them.</small></details>`;
}
export function readUpstreamTLS(data: FormData): UpstreamTLS {
  return {
    server_name: String(data.get("upstream_tls_name") || "").trim(),
    trusted_certificates_pem: data.has("upstream_trust_enabled")
      ? String(data.get("upstream_trusted_certificates") || "").trim()
      : "",
  };
}
export function bindUpstreamCheck(
  form: HTMLFormElement,
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>,
) {
  const button = form.querySelector<HTMLButtonElement>("[data-test-upstream]")!,
    status = form.querySelector<HTMLElement>("[data-upstream-test-result]")!,
    trust = form.elements.namedItem(
      "upstream_trust_enabled",
    ) as HTMLInputElement,
    pem = form.elements.namedItem(
      "upstream_trusted_certificates",
    ) as HTMLTextAreaElement,
    identity = form.querySelector<HTMLElement>("[data-upstream-certificate]")!,
    hint = form.querySelector<HTMLElement>("[data-upstream-trust-hint]")!;
  let generation = 0,
    observed: PeerCertificate | undefined;
  const updateTrust = () => {
    trust.disabled = !pem.value.trim() && !observed?.can_trust;
  };
  updateTrust();
  const inputs = [
    "upstream",
    "hostnames",
    "preserve_host",
    "upstream_tls_name",
    "upstream_trusted_certificates",
    "upstream_trust_enabled",
  ];
  form.addEventListener("input", (event) => {
    const name = (event.target as HTMLInputElement).name;
    if (inputs.includes(name)) {
      generation++;
      status.textContent =
        "Upstream settings changed. Test again to check these values.";
      status.className = "muted";
      if (
        [
          "upstream",
          "hostnames",
          "preserve_host",
          "upstream_tls_name",
        ].includes(name)
      ) {
        observed = undefined;
        identity.hidden = true;
      }
      updateTrust();
    }
  });
  trust.addEventListener("change", () => {
    if (trust.checked && !pem.value.trim() && observed?.can_trust) {
      pem.value = observed.pem;
      hint.textContent =
        "This host will trust the displayed certificate after Save. Test again to confirm. Replace the pin when that certificate rotates, or import its issuing CA for renewals.";
    } else if (!trust.checked)
      hint.textContent =
        "Additional trust is off. Only standard system trust will be used after Save.";
  });
  button.addEventListener("click", async () => {
    const data = new FormData(form),
      upstream = String(data.get("upstream") || "").trim();
    if (!upstream) {
      status.textContent = "Enter an upstream URL first.";
      return;
    }
    const requestGeneration = ++generation;
    button.disabled = true;
    button.textContent = "Checking…";
    status.textContent = "Connecting from this Aegis replica…";
    status.className = "muted";
    try {
      const result = await api<{
        reachable: boolean;
        stage: string;
        message: string;
        status?: number;
        tls_verified: boolean;
        duration_ms: number;
        certificate?: PeerCertificate;
      }>("/upstreams/test", "POST", {
        upstream,
        upstream_tls: readUpstreamTLS(data),
        host_header: data.has("preserve_host")
          ? String(data.get("hostnames") || "")
              .split(/[\s,]+/)
              .filter(Boolean)[0] || ""
          : "",
      });
      if (!form.isConnected || requestGeneration !== generation) return;
      status.textContent = `${result.message}${result.status ? ` HTTP ${result.status}.` : ""}${result.tls_verified ? " TLS verified." : ""} (${result.duration_ms} ms)`;
      status.className =
        result.reachable && result.status && result.status < 400
          ? "success-text"
          : "error-text";
      observed = result.certificate;
      identity.replaceChildren();
      identity.hidden = !observed;
      if (observed) {
        const title = document.createElement("strong");
        title.textContent = "Backend certificate";
        identity.append(title);
        for (const text of [
          `Subject: ${observed.subject}`,
          `Issuer: ${observed.issuer}`,
          `Expires: ${new Date(observed.not_after).toLocaleDateString()}`,
          `SHA-256: ${observed.sha256}`,
          result.tls_verified
            ? "TLS verified using the current trust settings."
            : observed.can_trust
              ? "Verify this identity against the backend you intended, then check Trust a private upstream certificate."
              : "Fix the certificate name/validity problem before it can be trusted.",
        ]) {
          const row = document.createElement("p");
          row.textContent = text;
          identity.append(row);
        }
      }
      updateTrust();
    } catch (error) {
      if (form.isConnected && requestGeneration === generation) {
        status.textContent =
          error instanceof Error
            ? error.message
            : "Upstream test failed. Try again.";
        status.className = "error-text";
      }
    } finally {
      if (form.isConnected) {
        button.disabled = false;
        button.textContent = "Test upstream";
      }
    }
  });
}
