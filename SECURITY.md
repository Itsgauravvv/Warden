# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x (main) | Yes |

## Security Architecture & Guarantees

Warden is designed around defense-in-depth for multi-tenant LLM and AI Agent deployments:

1. **Tenant Isolation:** Every database query in `TenantRepository` is strictly scoped by `tenant_id`. Semantic Cache ("Echo") partitions are keyed by `(tenantId, policyHash, model)` so cached responses never cross tenant or policy boundaries.
2. **Encryption at Rest:** Upstream provider API keys and webhook signing secrets are encrypted using **AES-256-GCM** with unique random IVs before storage in SQLite/D1. Warden tenant API keys are hashed with **SHA-256** and never stored in plaintext.
3. **SSRF Protection:** Custom upstream base URLs and tenant webhook endpoints are validated against private IPv4/IPv6 ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` cloud metadata, `localhost`, and `::1`).
4. **Tamper-Evident Audit Ledger:** Audit logs are hash-chained with `SHA-256(prev_hash || canonical_json)` per tenant and sealed into HMAC-SHA256 signed batches. Any historical modification is detected and pinpointed by `GET /admin/v1/audit/verify`.
5. **Sandbox-Only Red Teaming:** Imp Siege Mode (`POST /admin/v1/redteam/siege`) enforces `tenant.isSandbox === true` and returns `403 sandbox_required` for production tenants.
6. **Signed Webhooks:** Outbound webhooks include `X-Warden-Signature-256: sha256=<hmac>` and `Idempotency-Key` headers, with exponential backoff retries and Dead-Letter Queue tracking.

## Limitations & Probabilistic Detection Notice

No prompt-injection or DLP gateway can guarantee 100% detection against novel zero-day adversarial inputs. Treat Warden as a core enforcement layer within a broader defense-in-depth strategy alongside least-privilege agent credentials, strict tool JSON schemas, and human-in-the-loop approvals for destructive actions.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities. Instead, report privately via GitHub Security Advisories (or directly to the maintainers) with:
- A description of the vulnerability and affected package (`@warden/gateway`, `@warden/detectors`, etc.)
- Minimal reproduction steps or a failing Vitest case
- Suggested remediation if available

We aim to acknowledge reports within 48 hours and publish coordinated fixes with regression tests added to `@warden/eval`.