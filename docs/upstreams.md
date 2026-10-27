# Upstream connections and private TLS

Aegis connects to the upstream from its application container. A backend reachable from your browser may still have different container DNS, routing, firewall access or certificate trust.

## Test before saving

In **Applications → Add/Edit**, enter the upstream URL and click **Test upstream**. The check uses the currently entered URL, original Host-header choice, TLS server name and trusted certificates. It does not save the host or change routing. Changing these fields makes an earlier result stale.

The check sends a single GET from the management replica, waits up to eight seconds, follows no redirects and does not retain the response body. GET is used because some backends reject HEAD. It sends no browser cookies, application credentials or configured custom request headers; an authenticated backend may therefore return 401/403 even when it is reachable. The check does not create a continuous health monitor or prove all application routes work.

Results distinguish DNS, network connection, timeout, untrusted issuer, certificate-name mismatch and invalid certificate failures. An HTTP status means the backend responded: 401 indicates authentication may be required, 404 may indicate an incorrect path/Host header, and 5xx indicates an upstream application error. A redirect is reported without following it. TLS verification success is reported separately from the HTTP status.

The endpoint requires an administrator session/CSRF protection or a Configuration-scoped agent key. At most four tests run concurrently per replica. Tests generate an administrative audit event without recording certificate contents or URL paths. The test can reach private upstream addresses because configuring internal application targets is a management capability; it is not available to unauthenticated callers or Read-only agent keys.

## Trust a private CA or server certificate

Click **Test upstream**. If the issuer is unknown but the certificate covers the target and is currently valid, Aegis displays the subject, issuer, expiry and SHA-256 fingerprint. Verify that identity against your intended backend, then check **Trust a private upstream certificate**. That copies the displayed public certificate into the unsaved trust setting; Test again and Save to apply. Expired or name-mismatched certificates are not offered for this shortcut. It never disables verification.

For automatic renewals, prefer importing the private CA under **Upstream TLS → Trusted upstream certificates (PEM)** and checking the same trust checkbox:

- Prefer the private CA certificate that issued the backend certificate. Backend certificate renewal continues to work while the issuer remains trusted and its hostname/validity are correct.
- A public server certificate can be explicitly trusted as a pin. This trusts that exact certificate; update the pin when it rotates.
- Never provide a private key. Only certificate PEM blocks are accepted, up to 16 certificates and 64 KiB.

Obtain the certificate from a trusted administrative source and check its identity before importing it. Aegis keeps normal system trust and adds these certificates for this proxy host only. It continues verifying hostname, validity and TLS signatures. There is no global “ignore certificate errors” switch.

If the upstream URL uses an IP but the certificate covers only a DNS name, set **Upstream TLS server name** to the name covered by that certificate. This controls TLS SNI/verification, independently of **Preserve the original Host header**. The latter controls the HTTP Host header sent to the application.

Unchecking the checkbox keeps the entered certificates available in the form but stops using them after Save. A publicly trusted backend needs no extra trust; the checkbox is unavailable until a certificate has been imported or an eligible private certificate has been displayed.

Save the proxy host to apply trust. Settings live in PostgreSQL and refresh across replicas with normal configuration propagation. Existing upstream connections finish normally. Invalid settings fail the save and preserve the active configuration. Older API clients omitting `upstream_tls` on an update preserve the stored trust; send an empty object to clear it explicitly.

Public trust certificates are configuration, not private keys; they do not require the private-key encryption layer. Sealed snapshot recovery includes the host’s trust settings. PostgreSQL backups should retain them along with other site settings.

## Proxmox and similar private backends

A reachable `https://IP:8006` backend may use a Proxmox private CA that a browser or another proxy already trusts. Aegis needs that CA (or an explicit server-certificate pin) in its own per-host trust settings. Uploading a public visitor certificate to Aegis does not establish this separate upstream trust, and HSTS does not change it.
