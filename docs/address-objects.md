# Address objects and groups

Create reusable entries in **Address objects**. Each object has a name, description and exactly one value:

- IPv4 or IPv6 host: `192.0.2.10`, `2001:db8::10`.
- CIDR subnet: `192.168.10.0/24`, `2001:db8:1234::/48`.
- IPv4 subnet with contiguous dotted mask: `192.168.10.0/255.255.255.0` (a space instead of `/` is also accepted).

Network host bits are normalized; for example `192.168.10.42/24` becomes `192.168.10.0/24`. DNS names, address ranges, multiple values, interface zones and all-address `/0` networks are not supported. Use separate objects and groups for multiple addresses. Groups contain 1–128 objects; nested groups are not supported. Names are unique within objects and within groups, ignoring case. Maximum inventory: 1,024 objects and 128 groups.

Select objects or groups directly on a **Proxy host → Client identity, trusted proxies and exemptions** for trusted proxies, HTTP flood exemptions or bot exemptions. Existing literal CIDR settings remain valid and combine with references. Trust permits a proxy to supply sanitized identity headers; it does not exempt visitors from protections. Exemptions affect only their named component. Configure CIDR block/allow and Geo behavior in the assigned **Policy**, including whether allowed clients bypass Geo only or all WAF checks.

An object has no action by itself. The same object can be used for different purposes on different hosts/policies. **Agent access** keys also accept objects and groups for connecting source restrictions; an allowed source still needs a valid permitted API key.

Changes apply to every reference through the versioned in-memory configuration refresh (default two seconds, plus compilation time). No database lookup is added to forwarding. Administrators should review references before editing a shared object. Deletion is rejected while used by a group, current host/policy, or unexpired non-revoked agent key. Group edits that would exceed a consumer's expanded address limit are rejected atomically (32 trusted proxy entries, 128 per exemption/block/allow list). Historical policy revisions retain references; rolling back to deleted references is rejected rather than applying incomplete protections.

PostgreSQL is authoritative. Runtime database loss preserves the last active expanded proxy configuration. Optional sealed snapshot caches include expanded controls for offline recovery. Agent authorization fails closed during database loss.

## Local network location

Check **Local network** when creating or editing an IP object. Under **Address objects → Set local network location**, enter your gateway’s public IP address. Aegis uses the downloaded Country database (and optional City database) to assign that IP’s approximate country/region to future requests matching a local object. Enable/download Geo data from the Dashboard first. No external lookup is made for each request and the public IP is entered manually; update it if your WAN address changes.

The most-specific matching object wins. Equal-prefix objects must all be marked local to assign a location. Groups do not change this flag. Original client IPs and observed country remain available in request details. Assigned locations are labeled **Local network** in the dashboard and live map. Missing reference/Geo data is shown as unavailable rather than inventing a location. Existing log records are unchanged.

This is display metadata only: it does not trust a client, allow traffic, bypass protections, or change Geo-blocking, which always uses the actual resolved client IP. The setting and flags are stored in PostgreSQL and shared through the configuration cache (default two seconds); enrichment runs after forwarding. Optional sealed snapshots retain the local mapping.
