# Encryption at rest

Aegis encrypts certificate private keys, ACME account keys and saved provider credentials in the application before writing them to PostgreSQL. It uses AES-256-GCM with a fresh random nonce and authenticated purpose/key-identifier context. Encrypted bytes are stored in dedicated `bytea` columns. The 32-byte encryption key is supplied outside PostgreSQL, normally through a deployment secret file. Stored private keys and credential values are excluded from normal read APIs and audit entries.

Public certificate chains (`chain_pem`), hostnames, issuer, validity dates, configuration and logs are not encrypted by this application layer. No PostgreSQL table-wide or whole-database encryption is configured by Aegis.

An accurate product statement is: **Certificate private keys and ACME account keys are encrypted at rest using AES-256-GCM, with the encryption key stored outside the database.** A claim that all certificate records or the entire database are encrypted needs additional deployment-level storage encryption and confirmation that backups are also covered. Aegis does not inspect or attest to the host's storage encryption.

A database-only backup retains encrypted key material. Recovery also requires the external encryption key; keep its protected recovery copy separate from database backups. The key identifier supports future rotation design; automatic online key rotation is not implemented.
