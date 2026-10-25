import { esc } from "./ui";
export type AddressSelection = { object_ids: number[]; group_ids: number[] };
export type AddressObject = {
  id: number;
  name: string;
  description: string;
  value: string;
  is_local?: boolean;
};
export type AddressGroup = {
  id: number;
  name: string;
  description: string;
  object_ids: number[];
};
export type AddressInventory = {
  objects: AddressObject[];
  groups: AddressGroup[];
};
export const emptyInventory: AddressInventory = { objects: [], groups: [] };
export function addressPicker(
  name: string,
  label: string,
  selection: Partial<AddressSelection> | undefined,
  inventory: AddressInventory,
) {
  const selected = new Set([
    ...(selection?.object_ids || []).map((id) => "o:" + id),
    ...(selection?.group_ids || []).map((id) => "g:" + id),
  ]);
  return `<label class="field">${esc(label)}<select multiple name="${esc(name)}" aria-label="${esc(label)}" size="4"><optgroup label="Address groups">${inventory.groups.map((g) => `<option value="g:${g.id}" ${selected.has("g:" + g.id) ? "selected" : ""}>${esc(g.name)} · ${g.object_ids.length} objects</option>`).join("")}</optgroup><optgroup label="Address objects">${inventory.objects.map((o) => `<option value="o:${o.id}" ${selected.has("o:" + o.id) ? "selected" : ""}>${esc(o.name)} · ${esc(o.value)}</option>`).join("")}</optgroup></select></label><small>Select objects or groups; Ctrl/Command-click to select several. Manage entries in Address objects. ${inventory.objects.length ? "" : "Create an object first."}</small>`;
}
export function readAddressPicker(f: FormData, name: string): AddressSelection {
  const values = f.getAll(name).map(String);
  return {
    object_ids: values
      .filter((v) => v.startsWith("o:"))
      .map((v) => Number(v.slice(2))),
    group_ids: values
      .filter((v) => v.startsWith("g:"))
      .map((v) => Number(v.slice(2))),
  };
}
type C = {
  api: <T>(p: string, m?: string, b?: unknown) => Promise<T>;
  openEditor: (t: string, h: string) => void;
  closeEditor: () => void;
  formHandler: (id: string, fn: (f: FormData) => Promise<void>) => void;
  refresh: () => Promise<void>;
  notice: (m: string, e?: boolean) => void;
};
export function makeAddressObjects(c: C) {
  let inventory: AddressInventory = emptyInventory;
  async function load() {
    const [objects, groups] = await Promise.all([
      c.api<AddressObject[]>("/address-objects"),
      c.api<AddressGroup[]>("/address-groups"),
    ]);
    inventory = { objects, groups };
    return inventory;
  }
  async function render() {
    await load();
    const location = await c.api<{
      public_ip: string;
      country: string;
      region: string;
    }>("/geolocation/local");
    return `<div class="page-heading"><div><h1>Address objects</h1><p>Reusable IP addresses and networks. Each object has one address or subnet; groups collect objects.</p></div><div class="actions"><button class="secondary" data-action="address-group-new">New group</button><button class="primary" data-action="address-object-new">New object</button></div></div><section class="dashboard-panel"><h2>Local network location</h2><p>Use one public IP as the display-location reference for objects marked Local network. This does not change the actual client IP, trust, allowlists or Geo-blocking.</p><p>${location.public_ip ? `Reference: <strong>${esc(location.public_ip)}</strong> · ${esc(location.country || "Country unavailable; load Geo data from Dashboard")}${location.region ? " · " + esc(location.region) : ""}` : "No public IP reference configured."}</p><button class="secondary" data-action="address-local-location">Set local network location</button></section><section class="dashboard-panel"><h2>Objects</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Address / subnet</th><th>Description</th><th>Actions</th></tr></thead><tbody>${inventory.objects.map((o) => `<tr><td>${esc(o.name)}</td><td><code>${esc(o.value)}</code>${o.is_local ? "<small>Local network</small>" : ""}</td><td>${esc(o.description)}</td><td><button class="secondary" data-action="address-object-edit" data-id="${o.id}">Edit</button> <button class="danger" data-action="address-object-delete" data-id="${o.id}">Delete</button></td></tr>`).join("") || '<tr><td colspan="4">No address objects yet.</td></tr>'}</tbody></table></div></section><section class="dashboard-panel"><h2>Groups</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Members</th><th>Actions</th></tr></thead><tbody>${inventory.groups.map((g) => `<tr><td>${esc(g.name)}<small>${esc(g.description)}</small></td><td>${g.object_ids.map((id) => esc(inventory.objects.find((o) => o.id === id)?.name || id)).join(", ")}</td><td><button class="secondary" data-action="address-group-edit" data-id="${g.id}">Edit</button> <button class="danger" data-action="address-group-delete" data-id="${g.id}">Delete</button></td></tr>`).join("") || '<tr><td colspan="3">No groups yet.</td></tr>'}</tbody></table></div></section><div class="info-panel"><p>Select objects or groups on a proxy host for trusted proxies and component exemptions, or in a policy for block/allow lists. An object carries no allow/block action by itself. Edits apply to every reference within two seconds. Referenced entries cannot be deleted.</p></div>`;
  }
  async function handle(action: string | undefined, id: number) {
    if (!action?.startsWith("address-")) return false;
    if (action === "address-local-location") {
      const location = await c.api<{ public_ip: string }>("/geolocation/local");
      c.openEditor(
        "Local network location",
        `<form id="local-location-form"><label class="field">Gateway public IP<input name="public_ip" aria-label="Gateway public IP" value="${esc(location.public_ip)}" placeholder="Your gateway's public IPv4 or IPv6 address"></label><p>Local objects use this IP's cached country/region for future log/map entries. Original client IPs and observed Geo data remain available; Geo enforcement always uses the actual client IP. Leave empty to clear. This is not an automatic WAN-IP discovery service.</p><button class="primary" type="submit">Save local location</button></form>`,
      );
      c.formHandler("local-location-form", async (f) => {
        await c.api("/geolocation/local", "PUT", {
          public_ip: String(f.get("public_ip") || ""),
        });
        c.closeEditor();
        await c.refresh();
        c.notice(
          "Local location saved. New request logs update within two seconds; existing records retain their location.",
        );
      });
      return true;
    }
    await load();
    const group = action.startsWith("address-group-");
    const path = group ? "/address-groups" : "/address-objects";
    const item = group
      ? inventory.groups.find((g) => g.id === id)
      : inventory.objects.find((o) => o.id === id);
    const deleting = action.endsWith("-delete");
    if (!action.endsWith("-new") && !item)
      throw Error("This address entry no longer exists.");
    if (deleting) {
      c.openEditor(
        "Delete " + (group ? "group" : "object"),
        `<p>Delete ${esc(item?.name)}? References must be removed first.</p><form id="address-form"><button class="danger" type="submit">Delete</button></form>`,
      );
      c.formHandler("address-form", async () => {
        await c.api(path + "/" + id, "DELETE");
        c.closeEditor();
        await c.refresh();
        c.notice("Address entry deleted.");
      });
      return true;
    }
    c.openEditor(
      (item ? "Edit " : "New ") + (group ? "address group" : "address object"),
      `<form id="address-form"><label class="field">Name<input name="name" required maxlength="120" value="${esc(item?.name || "")}"></label><label class="field">Description<textarea name="description" maxlength="2000">${esc(item?.description || "")}</textarea></label>${group ? `<fieldset><legend>Member objects</legend>${inventory.objects.map((o) => `<label class="check"><input type="checkbox" name="object_id" value="${o.id}" ${(item as AddressGroup | undefined)?.object_ids?.includes(o.id) ? "checked" : ""}>${esc(o.name)} · ${esc(o.value)}</label>`).join("") || "<p>Create an address object first.</p>"}</fieldset>` : `<label class="field">IP address or subnet<input name="value" required value="${esc((item as AddressObject | undefined)?.value || "")}" placeholder="192.168.10.0/24"></label><small>One value per object. IPv4, IPv6, CIDR, or a subnet such as 192.168.10.0/255.255.255.0. Network addresses are normalized.</small><label class="check"><input type="checkbox" name="is_local" ${(item as AddressObject | undefined)?.is_local ? "checked" : ""}><span>Local network · use the gateway public IP location on maps</span></label><small>Configure Local network location on the Address objects page. Most-specific objects win; equal-prefix objects with mixed local settings remain unmapped. This changes display location only, not protection or trust.</small>`}<div class="form-actions"><button class="primary" type="submit">Save ${group ? "group" : "object"}</button></div></form>`,
    );
    c.formHandler("address-form", async (f) => {
      await c.api(path + (item ? "/" + id : ""), item ? "PUT" : "POST", {
        name: String(f.get("name")),
        description: String(f.get("description")),
        ...(group
          ? { object_ids: f.getAll("object_id").map(Number) }
          : { value: String(f.get("value")), is_local: f.has("is_local") }),
      });
      c.closeEditor();
      await c.refresh();
      c.notice("Address entry saved. References update within two seconds.");
    });
    return true;
  }
  return { load, render, handle };
}
