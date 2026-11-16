import { esc } from "./ui";
export type LogSettings = {
  retention_hours: number;
  audit_retention_hours: number;
  revision: number;
  last_cleanup_at: string | null;
  last_export_at: string | null;
  cleanup_error: string;
  export_error: string;
  access_deleted: number;
  audit_deleted: number;
  evidence_deleted: number;
  pending_access_export: boolean;
  pending_audit_export: boolean;
  unexported_access_logs: number;
  unexported_audit_events: number;
  log_storage_bytes: number;
  dropped_stdout_logs: number;
  dropped_database_logs: number;
};
const windows = [3, 6, 12, 24, 72, 168];
const auditWindows = [24, 72, 168, 720, 2160, 8760];
export function logStatusMarkup(s: LogSettings) {
  const at = (v: string | null) =>
    v ? new Date(v).toLocaleString() : "Waiting for first pass";
  return `<dl class="request-summary">${[
    [
      "Database log tables",
      `${(s.log_storage_bytes / 1048576).toFixed(1)} MiB`,
    ],
    [
      "Log retention windows",
      `${s.retention_hours} hours traffic · ${s.audit_retention_hours} hours audits`,
    ],
    ["Last stdout export check", at(s.last_export_at)],
    ["Last cleanup", at(s.last_cleanup_at)],
    [
      "Unexported backlog",
      s.unexported_access_logs || s.unexported_audit_events
        ? `${s.unexported_access_logs} traffic · ${s.unexported_audit_events} audit — retained until exported`
        : "None",
    ],
    [
      "Waiting for stdout export",
      s.pending_access_export || s.pending_audit_export
        ? "Stored records pending; retained until exported"
        : "No stored backlog",
    ],
    [
      "Records cleaned up",
      `${s.access_deleted} traffic · ${s.audit_deleted} audit · ${s.evidence_deleted} samples`,
    ],
    ["This replica: stdout drops / failures", String(s.dropped_stdout_logs)],
    ["This replica: records not persisted", String(s.dropped_database_logs)],
  ]
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
    .join(
      "",
    )}</dl>${s.export_error ? `<p role="alert" class="error-text">${esc(s.export_error)}</p>` : ""}${s.cleanup_error ? `<p role="alert" class="error-text">${esc(s.cleanup_error)}</p>` : ""}<p class="muted">Drop counters are since this replica started; cleanup totals are shared across replicas. Database table size includes reusable PostgreSQL space; cleanup does not necessarily shrink files on disk. The unexported backlog grows only while the stdout sink is failing; those rows are never deleted before a successful export.</p>`;
}
export function logSettingsMarkup(s: LogSettings) {
  return `<section class="dashboard-panel"><h2>Logs &amp; retention</h2><p>Every completed public request and committed administrative audit is sent to container stdout as structured JSON. Use your logging driver or SIEM for longer history.</p><form id="log-settings-form"><div class="form-grid"><label class="field">Traffic log retention<select name="retention_preset" aria-label="Traffic log retention">${windows.map((h) => `<option value="${h}" ${s.retention_hours === h ? "selected" : ""}>${h < 24 ? `${h} hours` : `${h / 24} days`}${h === 6 ? " · recommended" : ""}</option>`).join("")}<option value="custom" ${!windows.includes(s.retention_hours) ? "selected" : ""}>Custom</option></select></label><label class="field">Retention hours<input name="retention_hours" type="number" min="1" max="8760" step="1" required value="${s.retention_hours}"></label><label class="field">Administrative audit retention<select name="audit_retention_preset" aria-label="Administrative audit retention">${auditWindows.map((h) => `<option value="${h}" ${s.audit_retention_hours === h ? "selected" : ""}>${h < 24 ? `${h} hours` : `${h / 24} days`}${h === 720 ? " · default" : ""}</option>`).join("")}<option value="custom" ${!auditWindows.includes(s.audit_retention_hours) ? "selected" : ""}>Custom</option></select></label><label class="field">Audit retention hours<input name="audit_retention_hours" type="number" min="1" max="8760" step="1" required value="${s.audit_retention_hours}"></label></div><p class="muted">Traffic retention applies across all applications and replicas to traffic logs and captured samples. Administrative audits keep a separate forensic window that must be at least the traffic window, so audits survive past routine traffic deletion. The traffic window is a ceiling for captured samples: a site's longer capture expiry never extends sample life beyond it. Alerts and configuration revision history have separate lifecycles.</p><p>Saving a shorter window makes older records eligible for automatic deletion. Stored traffic and audit records are exported first; a failing stdout sink holds them indefinitely and grows the unexported backlog shown below. A successful stdout write does not confirm receipt by your SIEM.</p><div class="form-actions"><button type="submit" class="primary" data-label="Save log retention">Save log retention</button></div></form><h3>Logging status</h3><div id="log-retention-status" aria-live="polite">${logStatusMarkup(s)}</div><button type="button" class="secondary compact" id="refresh-log-status">Refresh logging status</button><p class="muted">Logging uses bounded background queues to keep forwarding responsive. Saturation or a process crash can lose queued records. Docker rotation and external collector retention are configured separately from this database window.</p></section>`;
}
export function bindLogSettings(
  view: HTMLElement,
  s: LogSettings,
  c: {
    api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
    formHandler: (
      id: string,
      submit: (data: FormData) => Promise<void>,
    ) => void;
    notice: (message: string, error?: boolean) => void;
    handleError: (error: unknown) => Promise<void>;
  },
  reload: () => Promise<void>,
) {
  const form = view.querySelector<HTMLFormElement>("#log-settings-form")!;
  const preset = form.elements.namedItem(
    "retention_preset",
  ) as HTMLSelectElement;
  const hours = form.elements.namedItem("retention_hours") as HTMLInputElement;
  const auditPreset = form.elements.namedItem(
    "audit_retention_preset",
  ) as HTMLSelectElement;
  const auditHours = form.elements.namedItem(
    "audit_retention_hours",
  ) as HTMLInputElement;
  preset.addEventListener("change", () => {
    if (preset.value !== "custom") hours.value = preset.value;
    else hours.focus();
  });
  hours.addEventListener("input", () => {
    preset.value = windows.includes(Number(hours.value))
      ? hours.value
      : "custom";
  });
  auditPreset.addEventListener("change", () => {
    if (auditPreset.value !== "custom") auditHours.value = auditPreset.value;
    else auditHours.focus();
  });
  auditHours.addEventListener("input", () => {
    auditPreset.value = auditWindows.includes(Number(auditHours.value))
      ? auditHours.value
      : "custom";
  });
  c.formHandler("log-settings-form", async (data) => {
    await c.api("/log-settings", "PUT", {
      retention_hours: Number(data.get("retention_hours")),
      audit_retention_hours: Number(data.get("audit_retention_hours")),
      revision: s.revision,
    });
    await reload();
    c.notice(
      "Log retention saved. Background cleanup removes eligible exported records.",
    );
  });
  const button = view.querySelector<HTMLButtonElement>("#refresh-log-status")!;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const next = await c.api<LogSettings>("/log-settings");
      if (view.isConnected)
        view.querySelector<HTMLElement>("#log-retention-status")!.innerHTML =
          logStatusMarkup(next);
    } catch (error) {
      await c.handleError(error);
    } finally {
      button.disabled = false;
    }
  });
}
