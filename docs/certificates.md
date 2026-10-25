# Certificates: setup, storage and renewal

## Choose how to obtain a certificate

Use **Certificates → Request certificate** for ACME, or **Upload PEM** for an existing certificate and matching key. The request form offers Cloudflare DNS-01 by default, with HTTP-01 and staging/custom ACME directories under Advanced options. CA terms acceptance is explicit.

| Method            | What you supply                                                                          | Validation                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloudflare DNS-01 | Domains, email and a scoped Cloudflare API token, or saved account/credential selections | A temporary public DNS TXT record. Supports wildcard certificates and does not require inbound port 80. Cloudflare must host the authoritative zone. |
| HTTP-01           | Domains and an ACME account                                                              | Public DNS and inbound port 80 must reach Aegis. Every replica can serve the shared challenge. Wildcards are not supported by HTTP-01.               |
| PEM upload        | Certificate chain and matching private key                                               | Aegis checks PEM/key format, key correspondence, validity dates and hostname coverage when assigning it to a site.                                   |

See [Cloudflare token permissions, propagation and cleanup](cloudflare.md) and [network requirements](deployment.md#certificate-and-upstream-connectivity). Issuing a wildcard certificate does not create wildcard proxy routes: hosts still use exact configured names.

## What PostgreSQL stores

| Material                                                        | Application storage protection                                                          |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Certificate private key                                         | AES-256-GCM encrypted bytes, with a key identifier.                                     |
| ACME account private key                                        | AES-256-GCM encrypted bytes.                                                            |
| Saved Cloudflare credentials                                    | AES-256-GCM encrypted bytes.                                                            |
| Public certificate chain, covered names, issuer and dates       | Stored as public certificate material/metadata; not encrypted by the application layer. |
| ACME accounts' non-secret metadata, orders, challenges and jobs | Stored in PostgreSQL for coordination and recovery; not whole-table encrypted by Aegis. |

The 32-byte encryption key stays outside PostgreSQL, normally in a deployment secret file. Encryption uses fresh random nonces and authenticated purpose/key-identifier context. Normal read APIs and audit events exclude stored private keys and credential values. Replicas decrypt the material they need into memory for TLS and issuance.

This is application-level encryption of secret values. Aegis does not configure PostgreSQL whole-database encryption or attest to host-volume/backup encryption. See [encryption at rest](encryption-at-rest.md) for the precise protection boundary and recovery requirements.

## Automatic and on-demand renewal

ACME certificates renew before expiry using the shorter of 30 days or one-third of their lifetime. Replicas share job state and use database coordination to prevent competing issuance for the same certificate. Saved ACME accounts and challenge credentials are reused.

To request a replacement early, open **Certificates → Details → Renew now**. This action is available only for ACME-managed certificates. It queues a job even before the normal renewal window and generates new TLS private-key material during issuance. An existing queued/running/retry job prevents duplicate jobs; use **Retry now** for a failed job. CA issuance limits still apply.

The existing certificate remains active until its validated replacement is committed. A failed renewal preserves the current material, reports an error and retries with backoff; an eventually expired certificate cannot keep serving TLS. Successful replacements propagate through the configuration refresh (default two seconds, plus loading time) without restarting replicas.

Uploaded certificates do not renew automatically. Use **Details → Replace PEM** with a new chain and key. A rejected replacement leaves the working certificate in place.

## Back up the key as well as the database

A PostgreSQL backup contains encrypted private keys; recovery also needs the external encryption key and matching key identifier. Protect a recovery copy of that key separately. The identifier supports future rotation design; automatic online rotation of the external encryption key is not implemented. Renewing a TLS certificate is a different operation from rotating that storage-encryption key.

Follow the [backup and recovery procedure](deployment.md#backups-and-recovery). No Certbot sidecar, shared certificate directory or persistent application volume is required by the default deployment.
