type Provider = {
  configured: boolean;
  base_url: string;
  has_api_key: boolean;
  model: string;
  models: string[];
  checked_at: string | null;
  revision: number;
};
type C = {
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
  esc: (v: unknown) => string;
  heading: (t: string, p: string, b?: string) => string;
  notice: (m: string, e?: boolean) => void;
  handleError: (e: unknown) => Promise<void>;
};
export function makeAIPage(c: C) {
  const { api, esc } = c;
  let current: Provider;
  let mounted: HTMLElement | null = null;
  let serial = 0;
  async function render(view: HTMLElement) {
    const stamp = ++serial;
    current = await api<Provider>("/ai/provider");
    if (stamp !== serial || !view.isConnected) return;
    mounted = view;
    view.innerHTML =
      c.heading(
        "AI backend",
        "Connect an OpenAI-compatible provider and choose a model.",
      ) +
      `<section class="dashboard-panel ai-settings"><form id="ai-form"><label class="field">API base URL<input name="base_url" type="url" required value="${esc(current.base_url || "https://api.openai.com/v1")}" placeholder="https://api.openai.com/v1"></label><small>Include the API prefix, usually /v1. Local providers can use HTTP on private networks; public providers require HTTPS.</small><label class="field">API key<input name="api_key" type="password" autocomplete="new-password" maxlength="4096" placeholder="${current.has_api_key ? "Saved securely; leave blank to keep it" : "Optional for providers without authentication"}"></label><label class="check"><input name="no_key" type="checkbox"><span>No API key · clear any saved key</span></label><small>Saved keys are encrypted and never returned. Changing endpoints requires a new key or an explicit choice to use no key.</small><div class="form-actions"><button type="button" class="secondary" id="ai-connect">Check connection & load models</button></div><div id="ai-test-status" role="status" aria-live="polite">${current.checked_at ? `Model list last checked ${esc(new Date(current.checked_at).toLocaleString())}.` : "Not connected yet."}</div><label class="field" for="ai-model">Model</label><select name="model" id="ai-model" ${current.models.length ? "" : "disabled"}><option value="">Select a model</option>${current.models.map((id) => `<option value="${esc(id)}" ${id === current.model ? "selected" : ""}>${esc(id)}</option>`).join("")}</select><small>The list may include embedding or audio models. Choose a text/chat model for future traffic analysis. Model discovery does not test inference or spend generation tokens.</small><div class="form-actions">${current.configured ? '<button type="button" class="danger" id="ai-remove">Remove provider</button>' : ""}<button type="submit" class="primary" id="ai-save" ${current.model ? "" : "disabled"}>Save provider</button></div></form></section><div class="info-panel"><h3>Traffic stays on the gateway</h3><p>This page configures connectivity only. Background traffic review and score-based rule proposals are not enabled yet. No traffic logs are submitted by these connection checks.</p></div>`;
    const form = view.querySelector<HTMLFormElement>("#ai-form")!;
    const base = form.elements.namedItem("base_url") as HTMLInputElement;
    const key = form.elements.namedItem("api_key") as HTMLInputElement;
    const noKey = form.elements.namedItem("no_key") as HTMLInputElement;
    const model = form.elements.namedItem("model") as HTMLSelectElement;
    const connect = view.querySelector<HTMLButtonElement>("#ai-connect")!;
    const save = view.querySelector<HTMLButtonElement>("#ai-save")!;
    const status = view.querySelector<HTMLElement>("#ai-test-status")!;
    let checkedBase = base.value;
    let busy = false;
    const input = () => ({
      base_url: base.value,
      api_key: noKey.checked ? "" : key.value,
      clear_api_key: noKey.checked,
      model: model.value,
      revision: current.revision,
    });
    const invalidate = () => {
      serial++;
      checkedBase = "";
      model.innerHTML =
        '<option value="">Check the connection to load models</option>';
      model.disabled = true;
      save.disabled = true;
      status.textContent = "Settings changed. Check the connection again.";
    };
    base.addEventListener("input", invalidate);
    key.addEventListener("input", invalidate);
    noKey.addEventListener("change", () => {
      key.disabled = noKey.checked;
      invalidate();
    });
    model.addEventListener("change", () => {
      save.disabled = busy || !model.value || checkedBase !== base.value;
    });
    connect.addEventListener("click", async () => {
      if (busy || !form.reportValidity()) return;
      busy = true;
      connect.disabled = true;
      save.disabled = true;
      const requestStamp = ++serial;
      const body = input();
      status.textContent = "Checking endpoint and loading models…";
      try {
        const result = await api<{ models: string[]; base_url: string }>(
          "/ai/provider/test",
          "POST",
          body,
        );
        if (requestStamp !== serial || !form.isConnected) return;
        checkedBase = base.value;
        model.innerHTML =
          '<option value="">Select a model</option>' +
          result.models
            .map(
              (id) =>
                `<option value="${esc(id)}" ${id === current.model ? "selected" : ""}>${esc(id)}</option>`,
            )
            .join("");
        model.disabled = !result.models.length;
        status.textContent = result.models.length
          ? `Connected · ${result.models.length} models available. Select a model and save.`
          : "Connected, but this provider returned no models.";
        save.disabled = !model.value;
      } catch (e) {
        if (requestStamp === serial && form.isConnected) {
          status.textContent =
            "Connection check failed. Saved configuration was not changed.";
          await c.handleError(e);
        }
      } finally {
        busy = false;
        if (form.isConnected) {
          connect.disabled = false;
          save.disabled = !model.value || checkedBase !== base.value;
        }
      }
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (busy || !model.value || checkedBase !== base.value) return;
      busy = true;
      save.disabled = true;
      connect.disabled = true;
      try {
        await api("/ai/provider", "PUT", input());
        if (!form.isConnected) return;
        await render(view);
        c.notice("AI provider saved. Traffic review remains disabled.");
      } catch (e) {
        await c.handleError(e);
      } finally {
        busy = false;
        if (form.isConnected) {
          connect.disabled = false;
          save.disabled = !model.value;
        }
      }
    });
    view.querySelector("#ai-remove")?.addEventListener("click", async () => {
      if (!confirm("Remove this AI provider and its saved key?")) return;
      try {
        await api("/ai/provider", "DELETE", { revision: current.revision });
        await render(view);
        c.notice("AI provider removed.");
      } catch (e) {
        await c.handleError(e);
      }
    });
  }
  return { render };
}
