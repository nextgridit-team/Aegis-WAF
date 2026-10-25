# Application architecture

Each replica runs the complete Go application: reverse proxy, management API/dashboard, configuration and certificate refresh, asynchronous logging, and coordinated background jobs. Production TypeScript assets are embedded in the Go application. The default Compose deployment adds only PostgreSQL.

```mermaid
flowchart TB
    clients["Application clients"] --> entry["Port mappings or external load balancer"]
    entry --> app1["Aegis replica 1"]
    entry --> app2["Aegis replica 2 · optional"]
    app1 --> upstream["Your HTTP(S) applications"]
    app2 --> upstream
    admin["Administrator browser · HTTPS"] -. "Separate management listener" .-> app1
    app1 <--> db[("PostgreSQL")]
    app2 <--> db
```

## State and the request path

PostgreSQL is authoritative for applications/hostnames/upstreams, certificates and encrypted keys, ACME state, administrator sessions, policies, logs and coordination. Deployment supplies database access, the external encryption key, listeners and the bootstrap secret. Application settings are changed through the dashboard/API.

Replicas cache active routes, policies and certificates in memory and poll configuration versions every two seconds by default. Compilation/loading can add propagation time. Routing and TLS selection do not query PostgreSQL for each decision. The request path resolves client identity, chooses cached protection, applies its decision, then attempts a nonblocking enqueue for logging.

A runtime database failure leaves existing replicas with their last loaded routes and valid certificates. Administrative/session operations still depend on PostgreSQL. A default cold start requires the database; optional [sealed snapshots](snapshot-cache.md) support explicitly configured recovery. Certificate expiration is still enforced.

## Coordination and scale

Replicas share ACME accounts, challenges and job state. Database locks coordinate issuance and renewal; sessions work across replicas without sticky routing. Every replica uses the same database and external encryption key. No Redis, separate worker image or Kubernetes component is required.

An external load balancer can distribute public traffic. Fixed Compose host-port mappings must be adjusted before scaling multiple replicas on one host. HTTP flood budgets remain per replica; increasing replica count increases the effective allowance. See [deployment and pooling constraints](deployment.md#multiple-replicas).

## Security and operations

The management listener is separate from protected listeners. The app container uses unprivileged internal ports, a read-only root and an explicit temporary directory. PostgreSQL owns default persistent application state; no persistent local app volume is needed unless optional snapshot recovery is enabled.

See [security boundaries](security.md), [certificate storage](certificates.md), [logging and worker recovery](logging.md) and [deployment](deployment.md). [Dashboard design notes](design.md) explain interface decisions separately from this runtime architecture.
