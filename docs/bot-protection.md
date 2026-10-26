# Selective self-hosted bot verification

Aegis can challenge suspicious requests without challenging every visitor. Enable **Anti-bot signals** and **Challenge suspected bots with self-hosted CAPTCHA** in a policy, then assign that policy to the application. Local application protection offers the same controls when no policy is assigned. Existing policies keep CAPTCHA disabled until explicitly configured.

Use Observe first: it records requests that would need verification and never displays a challenge. In Block, requests at or above the configured suspicion threshold require verification. Ordinary traffic below the threshold receives no challenge page or challenge cookie.

## Bounded, explainable suspicion

The initial implementation uses deterministic heuristics, not machine learning or Cloudflare/SafeLine's proprietary detection:

| Signal                                                          | Score |
| --------------------------------------------------------------- | ----: |
| Declared scanner User-Agent                                     |    80 |
| Declared headless browser                                       |    60 |
| Missing User-Agent when the corresponding setting is enabled    |    60 |
| Browser-like User-Agent with neither Accept nor Accept-Language |    25 |
| Common sensitive-path probe                                     |    35 |
| Request frequency above the configured rate/burst               |    40 |

Scores add up to at most 100. Default threshold: 60. Request-frequency signals default to 25 requests/second and a burst of 50; they are separate from enforcing flood budgets. Frequency alone does not cross the default threshold. A normal API client such as curl is not suspicious solely for being non-browser traffic. User-Agent and header signals can be spoofed; this is not verified-bot identity or adaptive behavioral learning.

## Verification and clearance

The image and English audio challenges use the pinned MIT-licensed `dchest/captcha` library. No challenge scripts, fonts or API calls go to another service. Public HTTPS is required, either directly on Aegis or through a configured trusted TLS-offloading proxy. Do not trust arbitrary forwarded headers.

Challenges expire after five minutes, allow five answer attempts and can be redeemed once across replicas. Answer material is AES-GCM encrypted in PostgreSQL using the external application key. Verification is server-side, with same-origin checks, a request token and protected cookies. Image/audio access is bounded and challenge generation has per-client and global limits. The reserved `/.aegis/challenge` namespace is handled by Aegis and never forwarded upstream.

A successful solve grants **bot-challenge clearance**, default 30 minutes and configurable from 1–120 minutes. It is bound to the application hostname, selected policy/revision/settings, resolved client IP and User-Agent. It is stored server-side in PostgreSQL with an opaque cookie and a bounded per-replica cache. Another replica can validate it against PostgreSQL without making a database query for every subsequent cached request. Policy/client changes or expiry require verification again.

Clearance suppresses repeat bot challenges. It does **not** bypass CIDR/Geo decisions, flood limits, custom rules or CRS signatures, and is not proof that every later request is safe. Trusted address-object/CIDR bot exemptions remain component-specific. No IP is permanently allowlisted after a solve.

## Browser, API and unsafe requests

Suspicious HTML GET requests receive a verification page. Other suspicious requests receive HTTP 403 JSON with `error: bot_verification_required`, a same-host `challenge_url` and retry guidance. Open that URL in a browser to complete the check, then explicitly retry the original API operation. Aegis does not buffer and automatically replay an unsafe POST/PUT body after a solve. Safe return paths are validated to prevent external redirects.

Use separate policies or explicit bot exemptions for trusted monitoring, service accounts, mobile/API clients and automation that cannot complete a browser challenge. Passing CAPTCHA does not authenticate an application user. Humans, solver services and capable bots can complete image/audio challenges; do not advertise complete bot prevention.

## Failure behavior and privacy

New challenges, answer verification and first-seen clearance on another replica require PostgreSQL. Failure returns an error rather than granting clearance. A replica with a valid cached clearance can retain it for its bounded lifetime during an outage; ordinary below-threshold requests continue using the loaded policy. A starting replica follows the existing configuration-readiness rules.

Challenge and clearance tables contain encrypted answers and keyed client/scope identifiers, not plaintext visitor IPs or User-Agents. These identifiers are pseudonymous data, not a guarantee of anonymity. Expired records are removed in bounded batches by a supervised cleanup loop every minute. Challenge state is globally bounded to 10,000 rows; clearance state to 100,000, with up to 10,000 cached clearances per replica. Issuance is capped at ten challenges per client-IP/application per minute, and media reads at twenty per challenge. Capacity exhaustion denies new verification rather than growing without bound.

Access details record suspicion score, reasons and challenge outcome. Challenge answers, cookies and raw challenge request facts are excluded from request-content evidence and normal telemetry. Gateway proof cookies are stripped before forwarding to applications. PostgreSQL backups and exported metadata follow operator retention controls.

See [policies](policies.md), [client identity and exemptions](headers-and-cidrs.md), [privacy](evidence-privacy.md) and [current limitations](limitations.md).

## Design references

[Cloudflare's rule-triggered challenges](https://developers.cloudflare.com/waf/custom-rules/use-cases/challenge-bad-bots/) and [clearance model](https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/) illustrate selective verification and bounded passage. [SafeLine](https://github.com/chaitin/SafeLine) also exposes anti-bot challenges. These references inform the workflow; Aegis does not use their hosted engines or claim equivalent classification accuracy. [dchest/captcha](https://github.com/dchest/captcha) supplies the local image/audio generation.

All serving replicas must run a build supporting bot verification before enabling it in a shared policy. During a rolling upgrade, leave the new setting disabled until every replica is updated. Application-specific response-header rewrites do not override the gateway-owned challenge page's CSP, content type, no-store policy or proof cookies; per-host HSTS still applies.
