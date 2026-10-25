# README graphics

These original graphics summarize implemented capabilities. They are illustrations, not screenshots, benchmark results or guarantees of attack coverage. The separate screenshots gallery records actual application captures.

- **aegis-overview.png** is an original generated feature illustration created from the shipped feature list on 2026-10-25. Its prompt used no reference images. It highlights certificates, Coraza/OWASP CRS policies, investigation and the two-container deployment. PEM uploads remain manual; automatic renewal applies to ACME certificates.
- **traffic-flow.svg** is an original, editable vector diagram authored for the README. It shows application traffic, optional bounded response inspection and the asynchronous access-log branch. PostgreSQL also stores configuration, sessions, jobs and coordination; those background paths are omitted from the traffic illustration. Administrative audit writes are transactional and are not described by the asynchronous access-log arrow.

Both reflect feature implementation `275af01a632d246b3eb5b8ccb5ef271da2ef10bc`. Neither uses the earlier demo infographics. Source/demo files remain untouched outside this graphics directory.

Read the [architecture](../architecture.md), [managed signatures](../managed-signatures.md), [inspection controls](../body-inspection.md), [logging](../logging.md) and [limitations](../limitations.md) before changing claims. The optional response checks do not cover arbitrary streams; flood budgets remain replica-local and bot signals are basic. This is a WAF and reverse proxy, not network-layer DDoS protection or an inference gateway.

Keep labels readable at GitHub content width, retain descriptive Markdown alt text, and keep the quickstart above detailed screenshots. This SVG has no scripts, external resources or motion. Check the rendered README at mobile and desktop widths after editing.
