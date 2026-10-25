import {
  addressPicker,
  readAddressPicker,
  emptyInventory,
  type AddressInventory,
} from "./address-objects";
import type { Protection } from "./dashboard";
const esc = (v: unknown) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
export function protectionOptions(
  p: Protection,
  inventory: AddressInventory = emptyInventory,
) {
  return `<h3>Client identity and trusted proxies</h3><p class="muted">Configure trust per proxy host when an F5 or another reverse proxy supplies client-IP headers. Enter the addresses that connect to Aegis and choose the header the proxy sanitizes. Trust permits identity headers; it does not allowlist visitors or bypass WAF protections.</p><label class="field" for="client-ip-source">Client IP header</label><select id="client-ip-source" name="client_ip_header">${[
    ["x-forwarded-for", "X-Forwarded-For · proxy chain"],
    ["x-real-ip", "X-Real-IP · single address"],
    ["cf-connecting-ip", "CF-Connecting-IP · Cloudflare"],
  ]
    .map(
      ([value, label]) =>
        `<option value="${value}" ${(p.client_ip_header || "x-forwarded-for") === value ? "selected" : ""}>${label}</option>`,
    )
    .join(
      "",
    )}</select>${addressPicker("trusted_addresses", "Trusted proxy objects / groups", p.trusted_addresses, inventory)}<label class="field">Trusted proxy CIDRs<textarea name="trusted_proxies" aria-label="Trusted proxy CIDRs" rows="2" placeholder="Proxy addresses only; leave empty for direct traffic">${esc((p.trusted_proxies || []).join("\n"))}</textarea></label><small>Only these proxies may supply client IP and protocol headers. Other connections use their socket IP. Configure this first when Aegis is behind a proxy.</small><h3>Protection exemptions</h3>${addressPicker("flood_exempt_addresses", "Flood exempt objects / groups", p.flood_exempt_addresses, inventory)}<label class="field">HTTP flood exempt IPs / CIDRs<textarea name="flood_exempt_cidrs" aria-label="HTTP flood exempt IPs / CIDRs" rows="3" placeholder="192.168.0.0/16&#10;2001:db8:1234::/48&#10;203.0.113.10/32">${esc((p.flood_exempt_cidrs || []).join("\n"))}</textarea></label><small>Matching clients bypass client and application flood budgets. Their requests still appear in logs and statistics.</small>${addressPicker("bot_exempt_addresses", "Anti-bot exempt objects / groups", p.bot_exempt_addresses, inventory)}<label class="field">Anti-bot exempt IPs / CIDRs<textarea name="bot_exempt_cidrs" aria-label="Anti-bot exempt IPs / CIDRs" rows="3" placeholder="Leave empty to apply bot checks to all clients">${esc((p.bot_exempt_cidrs || []).join("\n"))}</textarea></label><small>These exemptions apply only to the selected component. Other WAF rules remain active. Enter one IP or CIDR per line; private networks are included only when you add them.</small>`;
}
const cidrs = (v: FormDataEntryValue | null) =>
  String(v || "")
    .split(/[\s,]+/)
    .filter(Boolean);
export function readProtectionOptions(f: FormData) {
  return {
    trusted_addresses: readAddressPicker(f, "trusted_addresses"),
    flood_exempt_addresses: readAddressPicker(f, "flood_exempt_addresses"),
    bot_exempt_addresses: readAddressPicker(f, "bot_exempt_addresses"),
    trusted_proxies: cidrs(f.get("trusted_proxies")),
    client_ip_header: String(f.get("client_ip_header") || "x-forwarded-for"),
    flood_exempt_cidrs: cidrs(f.get("flood_exempt_cidrs")),
    bot_exempt_cidrs: cidrs(f.get("bot_exempt_cidrs")),
  };
}
