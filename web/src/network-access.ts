import {
  addressPicker,
  readAddressPicker,
  emptyInventory,
  type AddressInventory,
  type AddressSelection,
} from "./address-objects";
export type NetworkAccess = {
  block_addresses?: AddressSelection;
  allow_addresses?: AddressSelection;
  block_cidrs: string[];
  allow_cidrs: string[];
  allow_scope: string;
  geo_mode: string;
  geo_strategy: string;
  countries: string[];
  unknown_country: string;
};
export type NetworkDecision = {
  decision?: string;
  mode?: string;
  cidr?: string;
  allow_scope?: string;
  country?: string;
  geo_checked?: boolean;
  would_block?: boolean;
  blocked?: boolean;
  bypass_waf?: boolean;
};
export const networkDefaults = (
  value?: Partial<NetworkAccess>,
): NetworkAccess => ({
  block_addresses: value?.block_addresses,
  allow_addresses: value?.allow_addresses,
  block_cidrs: value?.block_cidrs || [],
  allow_cidrs: value?.allow_cidrs || [],
  allow_scope: value?.allow_scope || "geo",
  geo_mode: value?.geo_mode || "off",
  geo_strategy: value?.geo_strategy || "block_selected",
  countries: value?.countries || [],
  unknown_country: value?.unknown_country || "allow",
});
export function networkAccessMarkup(
  value: Partial<NetworkAccess> | undefined,
  esc: (v: unknown) => string,
  inventory: AddressInventory = emptyInventory,
) {
  const s = networkDefaults(value);
  const select = (
    name: string,
    label: string,
    current: string,
    options: [string, string][],
  ) =>
    `<label class="field">${label}<select name="${name}" aria-label="${label}">${options.map(([v, text]) => `<option value="${v}" ${v === current ? "selected" : ""}>${text}</option>`).join("")}</select></label>`;
  return `<details class="advanced"><summary>CIDR access and Geo blocking</summary><p class="muted">Order: client identity and policy selection → CIDR block → CIDR allow → Geo → other WAF protections. A block entry wins over an overlapping allow entry. Policy Off disables these controls; Observe records would-block decisions.</p>${addressPicker("network_block_addresses", "Block objects / groups", s.block_addresses, inventory)}<label class="field">CIDR block list<textarea name="network_block_cidrs" aria-label="CIDR block list" rows="2" placeholder="203.0.113.0/24">${esc(s.block_cidrs.join("\n"))}</textarea></label>${addressPicker("network_allow_addresses", "Allow objects / groups", s.allow_addresses, inventory)}<label class="field">CIDR allow list<textarea name="network_allow_cidrs" aria-label="CIDR allow list" rows="2" placeholder="Trusted client ranges, not proxy addresses">${esc(s.allow_cidrs.join("\n"))}</textarea></label>${select(
    "network_allow_scope",
    "CIDR allow behavior",
    s.allow_scope,
    [
      ["geo", "Bypass Geo only · keep other WAF protections"],
      ["all", "Bypass all WAF protections · trusted clients"],
    ],
  )}<small>An allow decision skips the Geo lookup. Full bypass also skips bot, flood and signature checks; routing, TLS and logging remain active. Only reliable resolved client identities can use an allow entry. Proxy trust stays on the proxy host.</small>${select(
    "network_geo_mode",
    "Geo mode",
    s.geo_mode,
    [
      ["off", "Off"],
      ["observe", "Observe · record and allow"],
      ["block", "Block · enforce geographical rules"],
    ],
  )}${select("network_geo_strategy", "Country list behavior", s.geo_strategy, [
    ["block_selected", "Block selected countries"],
    ["allow_selected", "Allow selected countries; block other known countries"],
  ])}<label class="field">Country codes<input name="network_countries" value="${esc(s.countries.join(", "))}" placeholder="US, CA, GB" aria-label="Country codes"></label>${select(
    "network_unknown_country",
    "Unknown location behavior",
    s.unknown_country,
    [
      ["allow", "Allow unknown locations · retain other WAF protections"],
      ["block", "Block unknown locations"],
    ],
  )}<small>Download the country database from Dashboard before enabling Geo. Lookups use cached local data, never a remote query per visitor. Unknown includes private IPs, missing records and unavailable data. IP location is approximate and can reflect VPN/proxy egress.</small></details>`;
}
export function readNetworkAccess(f: FormData): NetworkAccess {
  const list = (key: string) =>
    String(f.get(key) || "")
      .split(/[\s,]+/)
      .filter(Boolean);
  return {
    block_addresses: readAddressPicker(f, "network_block_addresses"),
    allow_addresses: readAddressPicker(f, "network_allow_addresses"),
    block_cidrs: list("network_block_cidrs"),
    allow_cidrs: list("network_allow_cidrs"),
    allow_scope: String(f.get("network_allow_scope") || "geo"),
    geo_mode: String(f.get("network_geo_mode") || "off"),
    geo_strategy: String(f.get("network_geo_strategy") || "block_selected"),
    countries: list("network_countries"),
    unknown_country: String(f.get("network_unknown_country") || "allow"),
  };
}
