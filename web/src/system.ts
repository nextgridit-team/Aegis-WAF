import { esc, heading, field, check } from "./ui";
type Settings = {
  backend: "memory" | "redis";
  address: string;
  username: string;
  tls: boolean;
  timeout_ms: number;
};
type Status = {
  settings: Settings;
  revision: number;
  has_password: boolean;
  loaded_revision: number;
  backend_failures: number;
};
type Context = {
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  formHandler: (id: string, submit: (data: FormData) => Promise<void>) => void;
  notice: (message: string, error?: boolean) => void;
  handleError: (error: unknown) => Promise<void>;
};
export function makeSystemPage(c: Context) {
  let serial = 0;
  async function render(view: HTMLElement) {
    const stamp = ++serial;
    const status = await c.api<Status>("/rate-state");
    if (stamp !== serial || !view.isConnected) return;
    const s = status.settings;
    view.innerHTML =
      heading(
        "System",
        "Configure shared rate budgets for replicated gateways.",
      ) +
      `<section class="dashboard-panel"><h2>Rate-limit state</h2><p>Rules, IP lists and policy settings already share PostgreSQL. Choose where live HTTP flood and bot-frequency counters are coordinated.</p><form id="rate-state-form"><label class="field">Counter backend<select name="backend"><option value="memory" ${s.backend === "memory" ? "selected" : ""}>Local memory · budget per replica</option><option value="redis" ${s.backend === "redis" ? "selected" : ""}>Redis / Dragonfly · shared budget</option></select></label><div id="redis-options" ${s.backend === "memory" ? "hidden" : ""}>${field("address", "Server address", s.address, "text", 'maxlength="300" placeholder="redis:6379"')}${field("username", "Username (optional)", s.username, "text", 'maxlength="128" autocomplete="off"')}${field("password", "Password (write only)", "", "password", `maxlength="4096" autocomplete="new-password" placeholder="${status.has_password ? "Stored · leave blank to keep" : "No stored password"}"`)}${check("clear_password", "Clear stored password")}${check("tls", "Use TLS with certificate verification", s.tls)}${field("timeout_ms", "Maximum counter lookup time (milliseconds)", String(s.timeout_ms), "number", 'min="20" max="250" required')}<p class="muted">Use a private backend shared by all replicas. Credentials are encrypted in PostgreSQL and never returned. Changing the address, username or TLS requires resupplying or explicitly clearing stored credentials.</p><button type="button" class="secondary" id="rate-test">Test connection</button><p id="rate-test-result" aria-live="polite"></p></div><p class="muted">If shared counters are unavailable, enforcing controls return 503. Observe records incomplete coverage. There is no automatic fallback to local budgets. Store restarts/eviction can reset counters; use a dedicated, non-evicting backend.</p><div class="form-actions"><button type="submit" class="primary" data-label="Save rate state">Save rate state</button></div></form><p>Saved revision ${status.revision} · this replica loaded ${status.loaded_revision} · backend failures ${status.backend_failures}</p></section><section class="info-panel"><h3>Deployment stays simple</h3><p>Local mode needs only Aegis and PostgreSQL. The optional Compose overlay adds a private Redis container; an existing Redis or Dragonfly endpoint can also be used. Configure settings here, then allow the normal two-second propagation interval. Test an application before enforcing.</p></section>`;
    const form = view.querySelector<HTMLFormElement>("#rate-state-form")!;
    const input = () => {
      const f = new FormData(form);
      return {
        backend: f.get("backend"),
        address: f.get("address"),
        username: f.get("username"),
        tls: f.has("tls"),
        timeout_ms: Number(f.get("timeout_ms")),
        password: f.get("password"),
        clear_password: f.has("clear_password"),
        revision: status.revision,
      };
    };
    form
      .querySelector<HTMLSelectElement>("[name=backend]")!
      .addEventListener("change", (e) => {
        view.querySelector<HTMLElement>("#redis-options")!.hidden =
          (e.target as HTMLSelectElement).value === "memory";
      });
    const button = view.querySelector<HTMLButtonElement>("#rate-test")!;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await c.api("/rate-state/test", "POST", input());
        view.querySelector<HTMLElement>("#rate-test-result")!.textContent =
          "Connection and authentication succeeded. Save to activate this backend.";
      } catch (error) {
        await c.handleError(error);
      } finally {
        button.disabled = false;
      }
    });
    c.formHandler("rate-state-form", async () => {
      await c.api("/rate-state", "PUT", input());
      await render(view);
      c.notice(
        "Rate-state settings saved. Replicas normally refresh within two seconds.",
      );
    });
  }
  return { render };
}
