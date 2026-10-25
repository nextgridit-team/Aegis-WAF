# Headers, trusted proxies and protection exemptions

In **Proxy hosts → Add/Edit**, use **Client identity, trusted proxies and exemptions** for client identity and CIDR exemptions, and **Proxy headers** for header forwarding and custom headers. Identity/exemptions are also available in **Dashboard → Protection settings**. Settings are application-specific, stored in PostgreSQL, audited transactionally, and cached on replicas. Changes propagate through the normal configuration-version refresh without per-request database reads.

## Forwarded identity

By default Aegis sends these upstream headers:

- `X-Forwarded-For`: the resolved client IP, replacing the supplied chain.
- `X-Real-IP`: the same resolved address.
- `X-Forwarded-Host`: the incoming Host value.
- `X-Forwarded-Proto`: actual HTTP/HTTPS, or a valid single `http`/`https` value supplied by a configured trusted proxy.
- `X-Forwarded-Port`: the incoming Host port, or the standard port for the resolved scheme.

The incoming forwarding/identity headers are discarded before generating these values. `Forwarded`, `CF-Connecting-IP`, `True-Client-IP` and `X-Client-IP` are not passed through as independent identities. Uncheck **Forward validated client headers to the upstream** to omit all managed identity headers. Custom header operations still work when forwarding is off. Existing Host preservation remains a separate setting.

By default the connection peer is the client; forwarding headers cannot change that. If Aegis receives traffic from a load balancer, list only that proxy's IPs/CIDRs under **Trusted proxy CIDRs** and select the header it sanitizes:

- **X-Forwarded-For:** walk the chain from the trusted transport peer towards the client, stopping at the first untrusted hop. Ignore forged prefixes beyond that hop.
- **X-Real-IP** or **CF-Connecting-IP:** require exactly one header containing one valid IP, supplied by a trusted transport peer.

Resolved identity is used consistently for upstream forwarding, rules, rate limits, logs, captured identity and geolocation. A missing/invalid header from a trusted proxy falls back to its transport address for logging and limiting, and is ineligible for CIDR exemptions. This avoids treating an unidentified external request as a trusted internal client. Direct trusted internal clients should not be indiscriminately included in the proxy-trust list.

Using Cloudflare DNS for ACME is separate from using Cloudflare as a traffic proxy. Trust headers only from the actual proxy addresses on your request path. Aegis cannot reconstruct original clients behind source NAT without a trustworthy identity source.

## Scoped CIDR exceptions

The lists accept individual IPv4/IPv6 addresses and CIDRs, separated by newlines, whitespace or commas. Individual addresses normalize to `/32` or `/128`; network host bits are masked. IPv4-mapped IPv6 normalizes to IPv4. At most 128 entries per exemption list and 32 trusted proxy entries are allowed. All-address `/0` entries are rejected; use Off to disable a component.

| List                          | Effect                                                               |
| ----------------------------- | -------------------------------------------------------------------- |
| Trusted proxy CIDRs           | May provide client identity/protocol; grants no protection exemption |
| HTTP flood exempt IPs / CIDRs | Skip client and whole-application flood budgets; consume neither     |
| Anti-bot exempt IPs / CIDRs   | Skip the basic bot detector for matched clients                      |

Each protection exception matches the resolved client IP, not an arbitrary supplied header. Other protection components and declarative WAF rules remain active. Traffic remains visible in logs, request/status totals, map and recent requests. Access metadata records `protection_exemptions` as `http_flood` and/or `anti_bot`; exempt traffic is not itself a suspicious signal. Dashboard and Activity show the reasons even if a different component blocks that request.

For example, to apply flood protection to external clients while excluding your LAN and a trusted office's public IP, enable flood protection, set your rates/bursts, then list the actual LAN CIDRs and that public `/32` in **HTTP flood exempt IPs / CIDRs**. Leave **Anti-bot exempt IPs / CIDRs** empty if those clients should still receive bot checks. No internal ranges are exempt by default.

## Custom headers

The request and response editors each support up to 32 **Set** or **Remove** operations. Set replaces all existing values with the configured value; Remove strips that header. Names are case-insensitive; duplicate/conflicting operations are rejected. Request operations affect upstream requests after security evaluation, so they do not alter incoming rule inspection. Response operations also apply to application blocks, redirects, upstream-error responses and protocol upgrades; they do not change the separate management listener.

Forwarding identity, Host, connection/framing and WebSocket handshake headers are gateway-managed and cannot be overridden through this editor. Use the dedicated forwarding/Host controls. Invalid names, CR/LF values, oversized values and conflicting operations are rejected without replacing working configuration. Static credential/cookie header injection is not supported; names treated as sensitive by the existing secret-field filter are rejected for Set. Removing ordinary authorization/cookie headers is supported. Header configuration is visible to administrators and is not a credential store. Values are not included in audit/service logs.

## API additions

`POST /api/sites` and `PUT /api/sites/{id}` accept optional `headers` and `protection` objects and save the entire application transactionally. Omitting either object on an update preserves its current settings. An explicit empty header object resets custom operations and uses standard forwarding.

```json
{
  "headers": {
    "forwarded_headers": "standard",
    "request_set": { "X-Application": "portal" },
    "request_remove": ["X-Unwanted"],
    "response_set": { "X-Frame-Options": "DENY" },
    "response_remove": ["Server"]
  }
}
```

Protection adds `client_ip_header` (`x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`), `flood_exempt_cidrs`, and `bot_exempt_cidrs`. These can also be saved through `PUT /api/protection-settings/{site_id}` with the existing rate/burst/mode settings. Authentication, CSRF and audit rules are unchanged.

## F5 and other upstream proxies

Trust is configured per proxy host, independently of reusable protection policies. Enter the F5's actual source addresses as seen by Aegis, then select a client-IP header that it supplies and sanitizes. For a sanitized X-Forwarded-For chain, Aegis walks right to left from the trusted connection peer and stops at the first untrusted address. Do not put visitor ranges in the proxy-trust field: trusting a proxy authorizes its identity headers and does not allowlist its visitors or bypass protections. A different application can use the same WAF policy with different trusted proxy settings.
