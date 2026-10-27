import { esc } from "./ui";
import { enhanceScale } from "./policy-editor-controls";
import type { ManagedSignatures } from "./signature-sets";
export type ConnectionLimits = {
  enabled: boolean;
  max_concurrent: number;
  max_per_client: number;
  max_duration_seconds: number;
  idle_timeout_seconds: number;
};
const defaults: ConnectionLimits = {
  enabled: false,
  max_concurrent: 100,
  max_per_client: 10,
  max_duration_seconds: 900,
  idle_timeout_seconds: 60,
};
export function policyAPIMarkup(managed: ManagedSignatures, isNew: boolean) {
  const window = managed.stream_window_bytes || 8192;
  return `<section class="policy-api-start"><h4>API starting settings</h4><p class="muted">For a new API or AI service, use Observe, Standard sensitivity, a 1 MiB request limit, common API methods and response checks off. Bot signals are turned off. Rules, assignments, flood rates and connection limits are kept.</p><button type="button" class="secondary compact" data-api-start>Use API starting settings</button><p data-api-start-status role="status"></p></section><details class="advanced"><summary>API methods and stream inspection</summary><label class="check"><input type="checkbox" name="signature_methods_auto" ${managed.allowed_methods?.length ? "" : "checked"}><span>Use endpoint method defaults</span></label><small>Website uses the CRS source default (GET, HEAD, POST, OPTIONS in the bundled set). API/SSE also allow PUT, PATCH and DELETE. The CRS method-enforcement rule must be included for these settings to enforce.</small><div data-api-methods><div class="policy-method-chips">${["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].map((m) => `<button type="button" data-api-method="${m}" aria-pressed="false">${m}</button>`).join("")}</div><label class="field">CRS allowed HTTP methods<input name="signature_allowed_methods" value="${esc((managed.allowed_methods || []).join(", "))}" placeholder="GET, POST, PUT"></label><small>Choose up to 16 methods. TRACE and CONNECT are excluded from the automatic defaults. This setting does not grant upstream authorization.</small></div><label class="check"><input name="signature_stream_window_policy" type="checkbox" ${isNew || managed.stream_window_bytes ? "checked" : ""}><span>Set the streaming inspection window in this policy</span></label><div data-policy-stream-window><label class="field">Streaming inspection window (KiB)<input name="signature_stream_window_kib" type="number" min="4" max="64" step="any" required value="${window / 1024}"></label></div><small>When unchecked, existing proxy-host window settings remain the compatibility fallback. A policy override is capped by its response-body limit. SSE checks run after delivery: Block can stop future output, not recall sent bytes. Each window has its own score.</small><p class="muted">Prompts containing SQL, HTML or attack examples can match website signatures. Keep new AI services in Observe while reviewing matches and narrow exceptions. The API preset does not disable SQLi/XSS protection or claim prompt-injection detection.</p></details>`;
}
export function connectionLimitsMarkup(saved?: ConnectionLimits) {
  const v = { ...defaults, ...saved };
  const number = (name: string, title: string, value: number, max: number) =>
    `<label class="field">${title}<input name="${name}" type="number" min="1" max="${max}" required value="${value}"></label>`;
  return `<details class="advanced"><summary>Connection and stream limits</summary><label class="check"><input name="connection_limits_enabled" type="checkbox" ${v.enabled ? "checked" : ""}><span>Enable connection and stream limits</span></label><p class="muted">Per application, selected policy and replica, including when rate counters use Redis. Block enforces; Observe records exceedances; Off pauses these controls. Full WAF bypass skips them.</p><div class="form-grid" data-connection-limits>${number("connection_max", "Concurrent requests per application", v.max_concurrent, 10000)}${number("connection_client_max", "Concurrent requests per client", v.max_per_client, 10000)}${number("connection_duration", "Maximum request duration (seconds)", v.max_duration_seconds, 86400)}${number("connection_idle", "Upstream idle timeout (seconds)", v.idle_timeout_seconds, 3600)}</div><small>Counts include long-lived SSE requests and other admitted upstream requests. Rejected requests get 429. Duration/idle failures before response headers get 504; after streaming starts the connection can end with its original status. Client caps use resolved IPs, so shared public IPs share a budget. WebSocket frame activity is not idle-inspected; the maximum duration still applies.</small></details>`;
}
export function mountPolicyAPI(
  form: HTMLFormElement,
  saved?: ConnectionLimits,
) {
  const field = (name: string) =>
    form.elements.namedItem(name) as HTMLInputElement;
  const auto = field("signature_methods_auto"),
    methods = field("signature_allowed_methods"),
    useWindow = field("signature_stream_window_policy"),
    window = field("signature_stream_window_kib"),
    enabled = field("connection_limits_enabled");
  let changedLimits = !!saved;
  const update = () => {
    form.querySelector<HTMLElement>("[data-api-methods]")!.hidden =
      auto.checked;
    form.querySelector<HTMLElement>("[data-policy-stream-window]")!.hidden =
      !useWindow.checked;
    form.querySelector<HTMLElement>("[data-connection-limits]")!.hidden =
      !enabled.checked;
    const set = new Set(methods.value.toUpperCase().split(/[\s,]+/));
    form
      .querySelectorAll<HTMLButtonElement>("[data-api-method]")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(set.has(b.dataset.apiMethod!))),
      );
    methods.setCustomValidity(
      !auto.checked && !methods.value.trim()
        ? "Choose at least one allowed method or use endpoint defaults."
        : "",
    );
  };
  form
    .querySelectorAll<HTMLButtonElement>("[data-api-method]")
    .forEach((button) =>
      button.addEventListener("click", () => {
        const set = new Set(
          methods.value
            .toUpperCase()
            .split(/[\s,]+/)
            .filter(Boolean),
        );
        const name = button.dataset.apiMethod!;
        if (set.has(name)) set.delete(name);
        else set.add(name);
        methods.value = [...set].join(", ");
        methods.dispatchEvent(new Event("input", { bubbles: true }));
      }),
    );
  auto.addEventListener("change", update);
  methods.addEventListener("input", update);
  useWindow.addEventListener("change", update);
  enabled.addEventListener("change", () => {
    changedLimits = true;
    update();
  });
  const validate = () => {
    const max = field("connection_max"),
      client = field("connection_client_max");
    client.setCustomValidity(
      Number(client.value) > Number(max.value)
        ? "The client cap cannot exceed the application cap."
        : "",
    );
  };
  for (const name of [
    "connection_max",
    "connection_client_max",
    "connection_duration",
    "connection_idle",
  ])
    field(name).addEventListener("input", () => {
      changedLimits = true;
      validate();
    });
  for (const [name, unit, lo, hi] of [
    [
      "connection_max",
      "concurrent requests",
      "Fewer connections",
      "More connections",
    ],
    [
      "connection_client_max",
      "concurrent requests per client",
      "Fewer connections",
      "More connections",
    ],
    ["connection_duration", "seconds", "Shorter requests", "Longer requests"],
    [
      "connection_idle",
      "seconds without progress",
      "Shorter idle period",
      "Longer idle period",
    ],
    [
      "signature_stream_window_kib",
      "KiB per inspection window",
      "Smaller windows",
      "Larger windows",
    ],
  ])
    enhanceScale(field(name), {
      unit,
      low: lo,
      high: hi,
      log: name.startsWith("connection_"),
    });
  form
    .querySelector<HTMLButtonElement>("[data-api-start]")!
    .addEventListener("click", () => {
      for (const [name, value] of [
        ["mode", "observe"],
        ["signature_mode", "observe"],
        ["signature_paranoia", "1"],
        ["signature_threshold", "5"],
        ["signature_outbound_threshold", "4"],
        ["signature_body_kib", "1024"],
        ["signature_body_action", "reject"],
        ["signature_response_mode", "off"],
      ]) {
        const control = form.elements.namedItem(name) as
          | HTMLInputElement
          | HTMLSelectElement;
        control.value = value;
        control.dispatchEvent(new Event("input", { bubbles: true }));
        control.dispatchEvent(new Event("change", { bubbles: true }));
      }
      for (const name of [
        "bot_enabled",
        "bot_challenge_enabled",
        "block_empty_user_agent",
      ]) {
        field(name).checked = false;
        field(name).dispatchEvent(new Event("change", { bubbles: true }));
      }
      auto.checked = false;
      methods.value = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";
      useWindow.checked = true;
      window.value = "8";
      for (const control of [auto, methods, useWindow, window]) {
        control.dispatchEvent(new Event("input", { bubbles: true }));
        control.dispatchEvent(new Event("change", { bubbles: true }));
      }
      update();
      form.querySelector<HTMLElement>("[data-api-start-status]")!.textContent =
        "API starting values applied to this form. Review the selected rules, methods and application assignments, then Save policy.";
    });
  update();
  validate();
  return () => ({
    ...(auto.checked
      ? {}
      : {
          allowed_methods: methods.value
            .toUpperCase()
            .split(/[\s,]+/)
            .filter(Boolean),
        }),
    ...(useWindow.checked
      ? { stream_window_bytes: Number(window.value) * 1024 }
      : {}),
    connection_limits: changedLimits
      ? {
          enabled: enabled.checked,
          max_concurrent: Number(field("connection_max").value),
          max_per_client: Number(field("connection_client_max").value),
          max_duration_seconds: Number(field("connection_duration").value),
          idle_timeout_seconds: Number(field("connection_idle").value),
        }
      : undefined,
  });
}
