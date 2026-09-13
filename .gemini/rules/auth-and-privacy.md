# Authentication, privacy, and operational logging

- Register every endpoint exposing Fail2Ban state through the same authentication
  path as `/metrics`. Preserve `/metrics.json` parity for both legacy basic auth
  and exporter-toolkit web configuration, including conditional and HEAD requests.
- Auth is optional today. Do not describe default deployments as authenticated.
  Use exporter-toolkit for TLS, mTLS, and web-config users; do not introduce a
  second homemade TLS or password-verification system.
- Preserve configuration validation rejecting mixed web-config and legacy auth
  or incomplete legacy credentials. Test middleware wiring, not just helpers.
- `/health` bypasses the legacy auth middleware but remains inside the toolkit
  listener. Preserve minimal-health mode and ensure probes do not increment
  scrape error counters, consume alert edges, or leak ban details.
- Customer/tenant labels identify series only. They do not establish a tenant
  boundary, filter data per caller, or replace endpoint authentication.
- Apply IP anonymization to every exported IP, including JSON pattern objects.
  Perform geo lookups and pattern analysis on real addresses internally. Preserve
  mask collision rules and stable-salt behavior documented in the README/schema.
- Never log credentials, Authorization headers, hash salts, private keys, or
  whole ban payloads. Do not add raw IP logging that defeats privacy settings.
- Log actionable failures with operation and outcome; avoid a new log line per
  IP per scrape. Metrics and diagnostics are not evidence of regulatory compliance.
  There is no product audit database or retention policy in this exporter.
