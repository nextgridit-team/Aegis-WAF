import { esc, heading, dateTime } from "./ui";
import {
  addressPicker,
  readAddressPicker,
  type AddressObject,
  type AddressGroup,
  type AddressSelection,
} from "./address-objects";
type Key = {
  id: number;
  name: string;
  prefix: string;
  scopes: string[];
  allowed_addresses: AddressSelection;
  expires_at: string;
  revoked_at: string | null;
};
type C = {
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
  notice: (m: string, e?: boolean) => void;
  handleError: (e: unknown) => Promise<void>;
  openEditor: (t: string, h: string) => void;
  formHandler: (id: string, fn: (f: FormData) => Promise<void>) => void;
  closeEditor: () => void;
};
export function makeAgentAccess(c: C) {
  let serial = 0;
  async function render(view: HTMLElement) {
    const stamp = ++serial;
    const [settings, keys, objects, groups] = await Promise.all([
      c.api<{ enabled: boolean; endpoint: string }>("/agent-access"),
      c.api<Key[]>("/agent-keys"),
      c.api<AddressObject[]>("/address-objects"),
      c.api<AddressGroup[]>("/address-groups"),
    ]);
    if (stamp !== serial || !view.isConnected) return;
    view.innerHTML =
      heading(
        "Agent access",
        "Connect your own AI agent through MCP. Your agent chooses its model and workflow; Aegis enforces access and validates changes.",
      ) +
      `<section class="dashboard-panel"><form id="agent-toggle-form"><label class="check"><input name="enabled" type="checkbox" role="switch" ${settings.enabled ? "checked" : ""}><span>Enable MCP endpoint</span></label><p>Endpoint: <code>${esc(location.origin + "/mcp")}</code></p><p class="muted">Streamable HTTP with a bearer API key. Disabled by default. No model runs here, and requests never wait on an agent.</p><button class="primary" type="submit">Save access setting</button></form></section><section class="dashboard-panel"><h2>Agent API keys</h2><p><a class="secondary" href="/api/agent-access/skill" download="aegis-waf.zip">Download agent skill</a> Import the bundled SKILL.md and playbooks, or ask the connected agent to call <code>get_agent_skill</code>. Adapt these to your own automation policy.</p><p>Keys are shown once, stored as hashes, expire automatically and can be revoked. Permissions apply across the workspace. Allowed source addresses use the socket peer; forwarded headers do not grant access.</p><button class="primary" id="agent-new-key">Create API key</button><div class="table-wrap"><table><thead><tr><th>Name</th><th>Permissions</th><th>Allowed addresses</th><th>Expires</th><th>Status</th></tr></thead><tbody>${keys.map((k) => `<tr><td>${esc(k.name)}<small>${esc(k.prefix)}…</small></td><td>${esc(k.scopes.join(", "))}</td><td>${[...(k.allowed_addresses.object_ids || []).map((id) => esc(objects.find((o) => o.id === id)?.name || "Removed object")), ...(k.allowed_addresses.group_ids || []).map((id) => esc(groups.find((g) => g.id === id)?.name || "Removed group"))].join(", ")}</td><td>${esc(dateTime(k.expires_at))}</td><td>${k.revoked_at ? "Revoked" : new Date(k.expires_at) <= new Date() ? "Expired" : `<button class="danger" data-agent-revoke="${k.id}">Revoke</button>`}</td></tr>`).join("") || '<tr><td colspan="5">No agent keys yet.</td></tr>'}</tbody></table></div></section><div class="info-panel"><h3>Bring your own workflow</h3><p>Drive the management API through scoped MCP operations: applications, routing, certificates, address objects, policies, rules, feeds, Geo, traffic capture, history and rollback. Account creation and new MCP keys remain console-only. Traffic can contain attacker-written instructions: treat it as untrusted data. Evidence access is a separate permission because it can contain sensitive request data.</p><p>Configure your client with this HTTPS URL and <code>Authorization: Bearer &lt;API key&gt;</code>. Clients must support custom bearer credentials; OAuth discovery and browser consent are not provided. Native management TLS is required for remote access.</p></div>`;
    const form = view.querySelector<HTMLFormElement>("#agent-toggle-form")!;
    form.onsubmit = async (e) => {
      e.preventDefault();
      try {
        await c.api("/agent-access", "PUT", {
          enabled: (form.elements.namedItem("enabled") as HTMLInputElement)
            .checked,
        });
        c.notice("Agent access updated.");
      } catch (e) {
        await c.handleError(e);
      }
    };
    view.querySelector<HTMLButtonElement>("#agent-new-key")!.onclick = () => {
      c.openEditor(
        "Create agent API key",
        `<form id="agent-key-form"><label class="field">Key name<input name="name" required maxlength="120" placeholder="Security review agent"></label><label class="field">Expires in days<input type="number" name="days" value="90" required min="1" max="365"></label><p>Read-only workspace metadata is included.</p>${[
          ["evidence", "Read retained evidence and replay rules"],
          ["draft", "Create disabled rule proposals"],
          [
            "configuration",
            "Manage applications, routing, address objects, Geo and traffic settings",
          ],
          [
            "certificates",
            "Manage certificates, DNS credentials and issuance jobs",
          ],
          [
            "agent_admin",
            "Inspect/revoke existing agent keys and change agent access",
          ],
          [
            "enforce",
            "Change live protections · rules, signatures, feeds and policies",
          ],
        ]
          .map(
            ([scope, label]) =>
              `<label class="check"><input type="checkbox" name="scope" value="${scope}"><span>${label}</span></label>`,
          )
          .join(
            "",
          )}${addressPicker("allowed", "Allowed source objects / groups", undefined, { objects, groups })}<small>At least one object or group is required. An IP allow entry restricts this key; it does not bypass API-key authentication.</small><div class="form-actions"><button type="submit" class="primary">Generate key</button></div></form>`,
      );
      c.formHandler("agent-key-form", async (f) => {
        const result = await c.api<{ api_key: string }>("/agent-keys", "POST", {
          name: String(f.get("name")),
          expires_in_days: Number(f.get("days")),
          scopes: ["read", ...f.getAll("scope").map(String)],
          allowed_addresses: readAddressPicker(f, "allowed"),
        });
        c.openEditor(
          "Save your API key",
          `<p>This key is shown once. Store it in your agent’s secret store.</p><label class="field">API key<input readonly type="password" id="agent-generated-key" value="${esc(result.api_key)}" autocomplete="off"></label><button type="button" id="agent-reveal-key" class="secondary">Show key</button> <button type="button" class="primary" data-action="cancel">Done</button>`,
        );
        document.querySelector<HTMLButtonElement>(
          "#agent-reveal-key",
        )!.onclick = () => {
          const input = document.querySelector<HTMLInputElement>(
            "#agent-generated-key",
          )!;
          input.type = input.type === "password" ? "text" : "password";
          input.select();
        };
        await render(view);
      });
    };
    view.querySelectorAll<HTMLButtonElement>("[data-agent-revoke]").forEach(
      (button) =>
        (button.onclick = () => {
          const id = Number(button.dataset.agentRevoke);
          c.openEditor(
            "Revoke agent key",
            `<p>Revoke this API key? New requests will be rejected on every replica. Already authorized operations may finish.</p><form id="agent-revoke-form"><button class="danger" type="submit">Revoke key</button></form>`,
          );
          c.formHandler("agent-revoke-form", async () => {
            await c.api("/agent-keys/" + id, "DELETE");
            c.closeEditor();
            await render(view);
            c.notice("API key revoked.");
          });
        }),
    );
  }
  return { render };
}
