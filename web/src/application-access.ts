import {
  actions,
  badge,
  check,
  dateTime,
  esc,
  field,
  heading,
  table,
} from "./ui";

type ProviderSettings = {
  name: string;
  type: "oidc" | "ldap";
  enabled: boolean;
  ca_pem?: string;
  oidc?: {
    issuer: string;
    client_id: string;
    scopes: string[];
    groups_claim: string;
  };
  ldap?: {
    url: string;
    bind_dn: string;
    user_base_dn: string;
    user_filter: string;
    username_attribute: string;
    email_attribute: string;
    groups_attribute: string;
    group_base_dn: string;
    group_filter: string;
    group_name_attribute: string;
  };
};
type Provider = {
  id: number;
  revision: number;
  settings: ProviderSettings;
  has_secret: boolean;
  applications?: { id: number; name: string }[];
};
type Access = {
  site_id: number;
  name: string;
  hostnames: string[];
  revision: number;
  settings: {
    enabled: boolean;
    provider_id: number;
    public_origin: string;
    allowed_groups: string[];
    allow_any_authenticated: boolean;
    session_minutes: number;
  };
};
type Session = {
  id: string;
  site_id: number;
  provider_id: number;
  identity: { username: string; subject: string };
  expires_at: string;
};
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  notice: (message: string, error?: boolean) => void;
  handleError: (error: unknown) => Promise<void>;
  openEditor: (title: string, html: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
};
const text = (data: FormData, key: string) =>
  String(data.get(key) || "").trim();
const lines = (value: string) =>
  value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
const textarea = (name: string, label: string, value: string, extra = "") =>
  `<label class="field">${label}<textarea name="${name}" rows="4" ${extra}>${esc(value)}</textarea></label>`;
const action = (
  name: string,
  label: string,
  id = "",
  style = "secondary compact",
) =>
  `<button type="button" class="${style}" data-access-action="${name}" data-id="${esc(id)}">${label}</button>`;

export function makeApplicationAccess(c: Context) {
  let providers: Provider[] = [],
    applications: Access[] = [],
    presets: ProviderSettings[] = [],
    currentView: HTMLElement,
    serial = 0;
  async function render(view: HTMLElement) {
    currentView = view;
    const stamp = ++serial;
    const result = await Promise.all([
      c.api<Provider[]>("/identity-providers"),
      c.api<Access[]>("/application-access"),
      c.api<ProviderSettings[]>("/identity-providers/presets"),
      c.api<Session[]>("/application-sessions"),
    ]);
    if (
      stamp !== serial ||
      !view.isConnected ||
      !location.hash.startsWith("#application-access")
    )
      return;
    [providers, applications, presets] = result;
    const sessions = result[3];
    const siteName = (id: number) =>
      applications.find((s) => s.site_id === id)?.name || `Application #${id}`;
    const providerName = (id: number) =>
      providers.find((p) => p.id === id)?.settings.name || "No provider";
    view.innerHTML =
      heading(
        "Application access",
        "Require sign-in before a request reaches your application. Choose a provider, assign groups, then verify a sign-in.",
        action("new", "Add identity provider", "", "primary"),
      ) +
      `<section class="dashboard-panel"><div class="section-heading"><h2>1. Identity providers</h2></div><p>OIDC connects to your sign-in provider, including its MFA. LDAP verifies passwords over TLS against your directory.</p>${
        providers.length
          ? table(
              ["Provider", "Type", "Status", "Applications", "Actions"],
              providers.map((p) => [
                esc(p.settings.name),
                p.settings.type.toUpperCase(),
                badge(
                  p.settings.enabled ? "Enabled" : "Disabled",
                  p.settings.enabled ? "success" : "neutral",
                ),
                esc(
                  (p.applications || []).map((s) => s.name).join(", ") ||
                    "Not assigned",
                ),
                action("test", "Test connection", String(p.id)) +
                  action("provider", "Edit", String(p.id)) +
                  action("delete", "Delete", String(p.id), "danger compact"),
              ]),
              "Identity providers",
            )
          : `<div class="simple-empty"><h3>Connect your identity provider</h3><p>Start with Authentik, Microsoft Entra ID, Google, OpenLDAP, Active Directory, or a custom OIDC provider.</p>${action("new", "Choose a provider", "", "primary")}</div>`
      }</section>` +
      `<section class="dashboard-panel"><div class="section-heading"><h2>2. Application assignments</h2></div><p>Login requirements apply in every WAF inspection mode. Public applications continue to use their existing protection policies.</p>${
        applications.length
          ? table(
              [
                "Application",
                "Access",
                "Provider",
                "Allowed identities",
                "Actions",
              ],
              applications.map((s) => [
                esc(s.name) +
                  `<small>${s.hostnames.map(esc).join(", ")}</small>`,
                badge(
                  s.settings.enabled ? "Sign-in required" : "Public",
                  s.settings.enabled ? "success" : "neutral",
                ),
                esc(providerName(s.settings.provider_id)),
                s.settings.enabled
                  ? s.settings.allow_any_authenticated
                    ? "Any authenticated identity"
                    : `${s.settings.allowed_groups.length} allowed groups / roles`
                  : "No sign-in requirement",
                action("application", "Configure access", String(s.site_id)) +
                  (s.settings.enabled
                    ? action(
                        "revoke-site",
                        "Revoke sessions",
                        String(s.site_id),
                      )
                    : ""),
              ]),
              "Application assignments",
            )
          : '<div class="simple-empty"><p>Add an application before assigning access.</p><a href="#applications">Open applications</a></div>'
      }</section>` +
      `<section class="dashboard-panel"><div class="section-heading"><h2>3. Active sessions</h2>${action("refresh", "Refresh")}</div><p>Group membership is checked at sign-in. Revoke sessions to require a new check before their expiry. Showing the newest 200 active sessions.</p>${
        sessions.length
          ? table(
              ["Identity", "Application", "Provider", "Expires", "Actions"],
              sessions.map((s) => [
                esc(s.identity.username || s.identity.subject),
                esc(siteName(s.site_id)),
                esc(providerName(s.provider_id)),
                esc(dateTime(s.expires_at)),
                action("revoke", "Revoke", s.id, "danger compact"),
              ]),
              "Application sessions",
            )
          : '<div class="simple-empty">No active application sessions.</div>'
      }</section>`;
    view.onclick = (e) => {
      const target = (e.target as HTMLElement).closest<HTMLButtonElement>(
        "[data-access-action]",
      );
      if (!target) return;
      void handle(target).catch(c.handleError);
    };
    const selected = Number(
      new URLSearchParams(location.hash.split("?")[1]).get("site_id"),
    );
    const application = applications.find((s) => s.site_id === selected);
    if (application && !document.querySelector("#editor[open]"))
      accessForm(application);
  }
  async function reload() {
    await render(currentView);
  }
  async function handle(button: HTMLButtonElement) {
    const id = button.dataset.id || "",
      kind = button.dataset.accessAction;
    if (kind === "new") {
      providerForm();
      return;
    }
    if (kind === "provider") {
      providerForm(providers.find((p) => p.id === Number(id)));
      return;
    }
    if (kind === "application") {
      const s = applications.find((s) => s.site_id === Number(id));
      if (s) accessForm(s);
      return;
    }
    if (kind === "refresh") {
      await reload();
      return;
    }
    if (
      kind === "delete" &&
      !confirm(
        "Delete this identity provider? Remove its application assignments first.",
      )
    )
      return;
    if (
      (kind === "revoke" || kind === "revoke-site") &&
      !confirm("Require the affected users to sign in again?")
    )
      return;
    button.disabled = true;
    try {
      if (kind === "test") {
        const result = await c.api<{ ok: boolean; message: string }>(
          `/identity-providers/${id}/test`,
          "POST",
          {},
        );
        c.notice(result.message, !result.ok);
        return;
      }
      if (kind === "delete") await c.api(`/identity-providers/${id}`, "DELETE");
      if (kind === "revoke")
        await c.api(`/application-sessions/${id}`, "DELETE");
      if (kind === "revoke-site")
        await c.api(`/application-access/${id}/revoke`, "POST", {});
      await reload();
      c.notice(
        kind === "delete"
          ? "Identity provider deleted."
          : "Sessions revoked. Users must sign in again.",
      );
    } finally {
      button.disabled = false;
    }
  }
  function providerForm(provider?: Provider, preset = 0) {
    const s = provider?.settings || presets[preset];
    if (!s) return;
    const oidc = s.type === "oidc",
      o = s.oidc,
      l = s.ldap;
    c.openEditor(
      provider ? "Edit identity provider" : "Connect an identity provider",
      `<form id="identity-provider-form">${!provider ? `<label class="field">Provider template<select name="preset">${presets.map((p, i) => `<option value="${i}" ${i === preset ? "selected" : ""}>${esc(p.name)} · ${p.type.toUpperCase()}</option>`).join("")}</select></label>` : `<p>${s.type.toUpperCase()} provider · Saving changes signs out existing application sessions.</p>`}${field("name", "Display name", s.name, "text", 'required maxlength="120"')}${check("enabled", "Provider enabled", s.enabled)}${
        oidc
          ? `${field("issuer", "Issuer URL", o?.issuer, "url", 'required placeholder="https://identity.example.com/"')}${field("client_id", "Client ID", o?.client_id, "text", "required")}${field("secret", "Client secret", "", "password", 'autocomplete="new-password" maxlength="8192"')}<p class="muted">${provider?.has_secret ? "A secret is saved. Leave blank to keep it. Re-enter it when changing the issuer, client ID or CA." : "Use the secret from your provider’s application registration. Public clients may leave it empty."}</p>${provider?.has_secret ? check("clear_secret", "Remove the saved client secret (public client)") : ""}${field("groups_claim", "Group / role claim", o?.groups_claim || "groups", "text", "required")}<p class="muted">Enter exact values from this claim when assigning an application. Entra application roles use <code>roles</code>; assign users or groups to those roles in Entra. Google does not provide Workspace groups in its ID token.</p><details><summary>Scopes and CA trust</summary>${field("scopes", "Scopes (space separated)", (o?.scopes || ["openid", "profile", "email"]).join(" "), "text", "required")}${textarea("ca_pem", "Additional trusted CA (PEM, optional)", s.ca_pem || "")}</details>`
          : `${field("url", "Directory URL", l?.url, "url", 'required placeholder="ldaps://directory.example.com:636"')}<p class="muted">Use LDAPS or ldap:// with mandatory StartTLS. Certificate verification is always enabled.</p>${field("bind_dn", "Service bind DN", l?.bind_dn, "text", 'required placeholder="cn=aegis,ou=service,dc=example,dc=com"')}${field("secret", "Service bind password", "", "password", `autocomplete="new-password" ${provider?.has_secret ? "" : "required"}`)}<p class="muted">${provider?.has_secret ? "Leave blank to keep the saved password. Re-enter it when changing the directory, bind DN or CA." : "Use a directory account that can read users and group membership."}</p>${field("user_base_dn", "User search base DN", l?.user_base_dn, "text", 'required placeholder="ou=people,dc=example,dc=com"')}${field("group_base_dn", "Group search base DN", l?.group_base_dn, "text", 'placeholder="ou=groups,dc=example,dc=com"')}<p class="muted">A group base enables group browsing and a membership search. Without it, membership comes from the configured user group attribute.</p><details><summary>Search filters, attributes and CA trust</summary>${field("user_filter", "User filter", l?.user_filter || "(uid={username})", "text", "required")}${field("group_filter", "Membership filter", l?.group_filter || "(member={dn})", "text", "required")}${field("username_attribute", "Username attribute", l?.username_attribute || "uid", "text", "required")}${field("email_attribute", "Email attribute", l?.email_attribute || "mail", "text", "required")}${field("groups_attribute", "User group attribute", l?.groups_attribute || "memberOf", "text", "required")}${field("group_name_attribute", "Group display attribute", l?.group_name_attribute || "cn", "text", "required")}${textarea("ca_pem", "Additional trusted CA (PEM, optional)", s.ca_pem || "")}</details>`
      }${actions(provider ? "Save provider" : "Save provider and test")}</form>`,
    );
    document
      .querySelector<HTMLSelectElement>(
        '#identity-provider-form [name="preset"]',
      )
      ?.addEventListener("change", (e) =>
        providerForm(undefined, Number((e.target as HTMLSelectElement).value)),
      );
    c.formHandler("identity-provider-form", async (data) => {
      const input: Record<string, unknown> = {
        name: text(data, "name"),
        type: s.type,
        enabled: data.has("enabled"),
        revision: provider?.revision || 0,
        secret: String(data.get("secret") || ""),
        clear_secret: data.has("clear_secret"),
        ca_pem: text(data, "ca_pem"),
      };
      if (oidc)
        input.oidc = {
          issuer: text(data, "issuer"),
          client_id: text(data, "client_id"),
          groups_claim: text(data, "groups_claim"),
          scopes: text(data, "scopes").split(/\s+/).filter(Boolean),
        };
      else
        input.ldap = Object.fromEntries(
          [
            "url",
            "bind_dn",
            "user_base_dn",
            "user_filter",
            "username_attribute",
            "email_attribute",
            "groups_attribute",
            "group_base_dn",
            "group_filter",
            "group_name_attribute",
          ].map((k) => [k, text(data, k)]),
        );
      const saved = await c.api<{ id: number }>(
        provider ? `/identity-providers/${provider.id}` : "/identity-providers",
        provider ? "PUT" : "POST",
        input,
      );
      c.closeEditor();
      await reload();
      c.notice("Provider saved. Testing connection…");
      const result = await c.api<{ ok: boolean; message: string }>(
        `/identity-providers/${saved.id}/test`,
        "POST",
        {},
      );
      c.notice(`Provider saved. ${result.message}`, !result.ok);
    });
  }
  function accessForm(application: Access) {
    const s = application.settings;
    c.openEditor(
      `Access for ${application.name}`,
      `<form id="application-access-form">${check("enabled", "Require sign-in for this application", s.enabled)}<label class="field">Identity provider<select name="provider_id"><option value="0">No provider</option>${providers.map((p) => `<option value="${p.id}" ${p.id === s.provider_id ? "selected" : ""}>${esc(p.settings.name)} · ${p.settings.type.toUpperCase()}${p.settings.enabled ? "" : " (disabled)"}</option>`).join("")}</select></label>${field("public_origin", "Public HTTPS origin", s.public_origin || `https://${application.hostnames[0]}`, "url", 'placeholder="https://app.example.com"')}<p class="muted">Use one of this application’s hostnames. Other aliases redirect here. HTTPS must be reachable before requiring sign-in.</p><div id="access-provider-help"></div><label class="field">Who can sign in?<select name="audience"><option value="groups" ${!s.allow_any_authenticated ? "selected" : ""}>Members of selected groups / roles</option><option value="any" ${s.allow_any_authenticated ? "selected" : ""}>Any identity authenticated by this provider</option></select></label><div id="access-groups">${textarea("allowed_groups", "Allowed groups / roles (one per line)", (s.allowed_groups || []).join("\n"))}<div id="access-group-search"></div></div><p class="muted" id="access-any-help" hidden>This permits every identity accepted by the provider. For Google, that can include any Google account. Apply tenant or user restrictions at the provider before enabling this option.</p>${field("session_minutes", "Session lifetime (minutes)", String(s.session_minutes || 30), "number", 'required min="5" max="1440"')}<p class="muted">5–1440 minutes. Group changes take effect on the next sign-in; saving this assignment revokes current sessions.</p>${actions("Save access settings")}</form>`,
    );
    const form = document.getElementById(
      "application-access-form",
    ) as HTMLFormElement;
    const providerSelect = form.elements.namedItem(
      "provider_id",
    ) as HTMLSelectElement;
    const origin = form.elements.namedItem("public_origin") as HTMLInputElement;
    const audience = form.elements.namedItem("audience") as HTMLSelectElement;
    const groups = form.elements.namedItem(
      "allowed_groups",
    ) as HTMLTextAreaElement;
    const update = () => {
      const p = providers.find((p) => p.id === Number(providerSelect.value));
      form.querySelector<HTMLElement>("#access-groups")!.hidden =
        audience.value === "any";
      form.querySelector<HTMLElement>("#access-any-help")!.hidden =
        audience.value !== "any";
      let publicOrigin = origin.value.replace(/\/$/, "");
      try {
        publicOrigin = new URL(origin.value).origin;
      } catch {
        /* Keep incomplete input visible while typing. */
      }
      const callback = publicOrigin + "/__aegis/auth/callback";
      form.querySelector("#access-provider-help")!.innerHTML =
        p?.settings.type === "oidc"
          ? `<label class="field">Register this redirect URI with your provider<input readonly aria-label="OIDC redirect URI" value="${esc(callback)}"></label><p class="muted">Use a web application with authorization code flow and PKCE. The group claim is <code>${esc(p.settings.oidc?.groups_claim || "groups")}</code>.</p>`
          : p
            ? '<p class="muted">Users sign in through an Aegis login page. Allowed groups must be full distinguished names. LDAP itself does not provide MFA.</p>'
            : '<p class="muted">Add and test a provider before requiring sign-in.</p>';
      form.querySelector("#access-group-search")!.innerHTML =
        p?.settings.type === "ldap"
          ? `${field("group_search", "Find a directory group", "", "search")}${action("search", "Search groups")}<div id="access-group-results" aria-live="polite"></div>`
          : '<p class="muted">Use exact, case-sensitive claim values. A missing group claim denies restricted access.</p>';
      form
        .querySelector('[data-access-action="search"]')
        ?.addEventListener("click", async (e) => {
          const button = e.currentTarget as HTMLButtonElement;
          button.disabled = true;
          try {
            const result = await c.api<{
              groups: { id: string; name: string }[];
              truncated: boolean;
            }>(`/identity-providers/${p!.id}/groups`, "POST", {
              search: (
                form.elements.namedItem("group_search") as HTMLInputElement
              ).value,
            });
            const container = form.querySelector("#access-group-results")!;
            container.innerHTML =
              result.groups
                .map(
                  (g, i) =>
                    `<p>${action("select-group", `Add ${esc(g.name || g.id)}`, String(i))}<small>${esc(g.id)}</small></p>`,
                )
                .join("") || '<p class="muted">No matching groups.</p>';
            if (result.truncated)
              container.insertAdjacentHTML(
                "beforeend",
                '<p class="muted">More groups exist. Narrow your search.</p>',
              );
            container
              .querySelectorAll<HTMLButtonElement>("button")
              .forEach((button) =>
                button.addEventListener("click", () => {
                  groups.value = [
                    ...new Set([
                      ...lines(groups.value),
                      result.groups[Number(button.dataset.id)].id,
                    ]),
                  ].join("\n");
                  button.disabled = true;
                  button.textContent = "Added";
                }),
              );
          } catch (error) {
            await c.handleError(error);
          } finally {
            button.disabled = false;
          }
        });
    };
    providerSelect.addEventListener("change", update);
    origin.addEventListener("input", update);
    audience.addEventListener("change", update);
    update();
    c.formHandler("application-access-form", async (data) => {
      await c.api(`/application-access/${application.site_id}`, "PUT", {
        revision: application.revision,
        enabled: data.has("enabled"),
        provider_id: Number(data.get("provider_id")),
        public_origin: text(data, "public_origin"),
        allowed_groups:
          data.get("audience") === "any"
            ? []
            : lines(text(data, "allowed_groups")),
        allow_any_authenticated: data.get("audience") === "any",
        session_minutes: Number(data.get("session_minutes")),
      });
      c.closeEditor();
      history.replaceState(null, "", "#application-access");
      await reload();
      c.notice(
        "Application access saved. Existing sessions have been revoked.",
      );
    });
  }
  return { render };
}
