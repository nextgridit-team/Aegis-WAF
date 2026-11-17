import qrcode from "qrcode-generator";
import { esc, heading, field, button, badge, table } from "./ui";

type Me = {
  username: string;
  csrf: string;
  role: string;
  mfa_enabled: boolean;
};
type SessionRow = {
  id: number;
  ip: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  current: boolean;
};
type Administrator = {
  id: number;
  username: string;
  role: string;
  mfa_enabled: boolean;
};
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
  notice: (message: string, error?: boolean) => void;
  handleError: (error: unknown) => Promise<void>;
  signOut: () => void;
};

const roleLabels: Record<string, string> = {
  owner: "Owner",
  operator: "Operator",
  read_only: "Read-only",
};

function qrSVG(uri: string): string {
  const qr = qrcode(0, "M");
  qr.addData(uri);
  qr.make();
  const n = qr.getModuleCount();
  let cells = "";
  for (let row = 0; row < n; row++)
    for (let col = 0; col < n; col++)
      if (qr.isDark(row, col)) cells += `M${col},${row}h1v1h-1z`;
  return `<svg class="mfa-qr" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="Authenticator enrollment QR code"><rect width="${n}" height="${n}" fill="#fff"/><path d="${cells}" fill="#000"/></svg>`;
}

export function makeAccountPage(c: Context) {
  let serial = 0;
  let enrollSecret = "";
  let enrollURI = "";
  async function render(view: HTMLElement) {
    const stamp = ++serial;
    const me = await c.api<Me>("/me");
    if (stamp !== serial || !view.isConnected) return;
    const sessions = await c.api<SessionRow[]>("/sessions");
    if (stamp !== serial || !view.isConnected) return;
    let admins: Administrator[] | null = null;
    try {
      admins = await c.api<Administrator[]>("/administrators");
    } catch {
      admins = null; // Listing administrators requires the owner role.
    }
    if (stamp !== serial || !view.isConnected) return;
    view.innerHTML =
      heading(
        "Account",
        "Your sign-in credentials, two-factor authentication and active sessions.",
      ) +
      passwordMarkup() +
      mfaMarkup(me) +
      sessionsMarkup(sessions) +
      (admins ? administratorsMarkup(admins, me) : "");
    bindPassword();
    bindMFA(view, me);
    bindSessions(view);
    if (admins) bindAdministrators(view);
  }

  function passwordMarkup() {
    return `<section class="dashboard-panel"><h2>Password</h2><p>Changing your password revokes every session, including this one. You will sign in again afterwards.</p><form id="password-form">${field("current_password", "Current password", "", "password", 'required autocomplete="current-password"')}${field("new_password", "New password", "", "password", 'required minlength="14" maxlength="72" autocomplete="new-password"')}<div class="form-actions"><button type="submit" class="primary" data-label="Change password">Change password</button></div></form></section>`;
  }

  function mfaMarkup(me: Me) {
    if (me.mfa_enabled) {
      return `<section class="dashboard-panel"><h2>Two-factor authentication</h2><p>A time-based one-time password (TOTP) is required at every sign-in. Disabling requires your current password plus a fresh code or an unused recovery code, and revokes every session.</p><form id="mfa-disable-form">${field("password", "Current password", "", "password", 'required autocomplete="current-password"')}${field("code", "Authenticator code or recovery code", "", "text", 'required maxlength="16" autocomplete="one-time-code" inputmode="numeric"')}<p class="muted">Lost your authenticator? Any unused recovery code works here.</p><div class="form-actions"><button type="submit" class="secondary" data-label="Disable two-factor">Disable two-factor</button></div></form></section>`;
    }
    return `<section class="dashboard-panel"><h2>Two-factor authentication</h2><p>Require a time-based one-time password from an authenticator app at every sign-in. Enrollment shows a QR code and a manual-entry key once, then single-use recovery codes.</p><div class="form-actions" id="mfa-enroll-actions"><button type="button" class="primary" id="mfa-enroll" data-label="Set up authenticator">Set up authenticator</button></div><div id="mfa-enroll-panel" hidden></div></section>`;
  }

  function enrollPanelMarkup() {
    return `<div class="mfa-enroll"><p>Scan this QR code with your authenticator app, or enter the key manually.</p><div class="mfa-qr-wrap">${qrSVG(enrollURI)}</div><label class="field" for="mfa-secret">Manual entry key</label><code id="mfa-secret" class="mfa-secret">${esc(enrollSecret)}</code><form id="mfa-confirm-form">${field("code", "Enter the current six-digit code to confirm", "", "text", 'required maxlength="6" pattern="[0-9]{6}" autocomplete="one-time-code" inputmode="numeric"')}<div class="form-actions"><button type="submit" class="primary" data-label="Confirm enrollment">Confirm enrollment</button></div></form><p class="muted">Confirming revokes every session — you will sign in again with your password and a code.</p></div>`;
  }

  function sessionsMarkup(rows: SessionRow[]) {
    return `<section class="dashboard-panel"><h2>Sessions</h2><p>Every signed-in browser for your account, across all replicas. Revoking a session takes effect on its next request.</p>${table(
      ["Session", "Address", "User agent", "Created", "Last seen", ""],
      rows.map((s) => [
        s.current ? "<strong>This session</strong>" : `Session #${s.id}`,
        esc(s.ip),
        `<span class="mono">${esc(s.user_agent)}</span>`,
        esc(new Date(s.created_at).toLocaleString()),
        esc(new Date(s.last_seen_at).toLocaleString()),
        s.current
          ? ""
          : `<button type="button" class="secondary" data-revoke="${s.id}">Revoke</button>`,
      ]),
      "Active sessions",
    )}<div class="form-actions"><button type="button" class="secondary" id="revoke-all-sessions">Revoke all sessions</button></div></section>`;
  }

  function administratorsMarkup(admins: Administrator[], me: Me) {
    return `<section class="dashboard-panel"><h2>Administrators</h2><p>Owners manage accounts and credential minting; operators run the workspace; read-only accounts can view but not change anything. Password, MFA and session management remain self-service for every administrator.</p>${table(
      ["Username", "Role", "MFA", ""],
      admins.map((a) => [
        `${esc(a.username)}${a.username === me.username ? " <small>(you)</small>" : ""}`,
        esc(roleLabels[a.role] ?? a.role),
        a.mfa_enabled ? badge("Enabled", "success") : badge("Off", "neutral"),
        a.username === me.username ? "" : roleSelect(a),
      ]),
      "Administrators",
    )}<form id="administrator-form">${field("username", "Username", "", "text", 'required minlength="3" maxlength="64" autocomplete="off"')}${field("password", "Initial password", "", "password", 'required minlength="14" maxlength="72" autocomplete="new-password"')}<label class="field" for="administrator-role">Role</label><select id="administrator-role" name="role"><option value="read_only">Read-only</option><option value="operator">Operator</option><option value="owner">Owner</option></select><div class="form-actions"><button type="submit" class="primary" data-label="Create administrator">Create administrator</button></div></form></section>`;
  }

  function roleSelect(a: Administrator) {
    return `<select data-role-for="${a.id}">${Object.entries(roleLabels)
      .map(
        ([value, label]) =>
          `<option value="${value}" ${a.role === value ? "selected" : ""}>${label}</option>`,
      )
      .join("")}</select>`;
  }

  function bindPassword() {
    c.formHandler("password-form", async (f) => {
      await c.api("/password", "POST", {
        current_password: f.get("current_password"),
        new_password: f.get("new_password"),
      });
      c.notice(
        "Password changed. Every session was revoked — sign in again.",
      );
      c.signOut();
    });
  }

  function bindMFA(view: HTMLElement, me: Me) {
    const enrollButton = view.querySelector<HTMLButtonElement>("#mfa-enroll");
    enrollButton?.addEventListener("click", async () => {
      enrollButton.disabled = true;
      try {
        const out = await c.api<{ secret: string; uri: string }>(
          "/mfa/enroll",
          "POST",
          {},
        );
        enrollSecret = out.secret;
        enrollURI = out.uri;
        const panel = view.querySelector<HTMLElement>("#mfa-enroll-panel");
        if (panel) {
          panel.innerHTML = enrollPanelMarkup();
          panel.hidden = false;
          bindConfirm(panel);
        }
      } catch (error) {
        await c.handleError(error);
      } finally {
        enrollButton.disabled = false;
      }
    });
    if (me.mfa_enabled) {
      c.formHandler("mfa-disable-form", async (f) => {
        await c.api("/mfa/disable", "POST", {
          password: f.get("password"),
          code: f.get("code"),
        });
        c.notice(
          "Two-factor authentication disabled. Every session was revoked — sign in again.",
        );
        c.signOut();
      });
    }
  }

  function bindConfirm(panel: HTMLElement) {
    c.formHandler("mfa-confirm-form", async (f) => {
      const out = await c.api<{ recovery_codes: string[] }>(
        "/mfa/confirm",
        "POST",
        { code: f.get("code") },
      );
      panel.innerHTML = `<p><strong>Two-factor authentication is enabled.</strong> Save these single-use recovery codes now — they are shown only once and each can unlock one sign-in if you lose your authenticator.</p><div class="recovery-codes">${out.recovery_codes
        .map((code) => `<code>${esc(code)}</code>`)
        .join("")}</div><p class="muted">Every session was revoked. Sign in again with your password and a code from your authenticator.</p>`;
      c.notice("Two-factor authentication enabled. Sign in again to use it.");
      c.signOut();
    });
  }

  function bindSessions(view: HTMLElement) {
    view
      .querySelectorAll<HTMLButtonElement>("[data-revoke]")
      .forEach((button) => {
        button.addEventListener("click", async () => {
          button.disabled = true;
          try {
            await c.api(`/sessions/${button.dataset.revoke}`, "DELETE");
            await render(view);
            c.notice("Session revoked.");
          } catch (error) {
            await c.handleError(error);
          }
        });
      });
    view
      .querySelector<HTMLButtonElement>("#revoke-all-sessions")
      ?.addEventListener("click", async (event) => {
        const button = event.currentTarget as HTMLButtonElement;
        button.disabled = true;
        try {
          await c.api("/sessions", "DELETE");
          c.notice("Every session was revoked — sign in again.");
          c.signOut();
        } catch (error) {
          await c.handleError(error);
        }
      });
  }

  function bindAdministrators(view: HTMLElement) {
    view
      .querySelectorAll<HTMLSelectElement>("[data-role-for]")
      .forEach((select) => {
        select.addEventListener("change", async () => {
          const id = select.dataset.roleFor;
          try {
            await c.api(`/administrators/${id}/role`, "PUT", {
              role: select.value,
            });
            c.notice("Administrator role updated.");
            await render(view);
          } catch (error) {
            await c.handleError(error);
            await render(view);
          }
        });
      });
    c.formHandler("administrator-form", async (f) => {
      await c.api("/administrators", "POST", {
        username: f.get("username"),
        password: f.get("password"),
        role: f.get("role"),
      });
      c.notice("Administrator created.");
      await render(view);
    });
  }

  return { render };
}
