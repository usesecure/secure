# Pattern Taxonomy

Use this as a second-pass checklist after the initial review. It is designed to catch semantic and structural failures that keyword reviews miss.

## 1. Naming Bias

Risk is inferred from names instead of behavior. Benign labels such as `preview`, `public`, `lead`, `template`, `sync`, `asset`, `download`, `helper`, `quote`, or `requirements` can still mutate state, spend money, expose files, or send messages.

## 2. Capability Blindness

The review misses what code can actually do: delete storage objects, generate signed URLs, flush cache, call AI, render PDFs, send email, enqueue jobs, or modify payment/visibility/role state.

## 3. Guard Dominance Failure

A guard exists but does not dominate the sink on all paths. Common forms: check after lookup leaks existence, list endpoint is scoped but direct update is not, role check exists but object ownership is skipped, fallback path bypasses the canonical helper.

## 4. Authentication-Authorization Collapse

The route checks "logged in" and then performs role-gated or object-scoped work. Authentication is treated as permission.

## 5. Tenant Boundary Drift

Tenant filtering appears in some reads but not direct reads, updates, deletes, signed URLs, storage prefixes, background jobs, audit logs, or exports.

## 6. Mass Assignment

User payloads can set policy fields: `role`, `tenantId`, `ownerId`, `organizationId`, `status`, `visibility`, `approvedAt`, `deletedAt`, `reviewerId`, `plan`, `price`, `quota`, `isAdmin`, `metadata`, or storage keys.

## 7. State-Invariant Loss

Mutations skip product invariants: cannot publish without review, cannot approve own work, cannot delete last admin, cannot restore deleted public content, cannot move private assets to public visibility, cannot downgrade payment records by client input.

## 8. Fail-Open/Fake-Success Behavior

Missing env vars, Redis outages, disabled providers, absent policy config, or external API failures return allow-like behavior, fake success, skipped checks, or default broad access.

## 9. Side-Effect Blindness

The response is small but the downstream effect is sensitive: email, webhook, chat, cache invalidation, search indexing, PDF generation, AI spend, storage writes, or operational alerts.

## 10. Public Resource Abuse

Public endpoints are rate-limited incorrectly or not at all, allowing spam, lead flooding, expensive AI calls, document rendering abuse, scraping, or storage amplification.

## 11. Secrets And Unsafe Examples

Tracked `.env`, examples, local tool config, deploy files, generated docs, screenshots, tests, or logs contain real-looking credentials, live URLs, or insecure defaults such as demo auth enabled. Example files are production risks because teams copy them.

## 12. CORS/CSRF False Comfort

The review sees CORS code and stops. Check credentials, cookie/session routes, preflight behavior, same-site assumptions, trusted origins per environment, and whether CORS is relevant to the threat.

## 13. Error And Log Disclosure

Responses or logs expose stack traces, `error.message`, provider payloads, tokens, storage keys, internal URLs, document contents, PII, payment details, or tenant identifiers.

## 14. Contract Verification Failure

Names such as `success`, `enabled`, `isAdmin`, `canAccess`, `public`, `safe`, `validate`, or `authorized` are trusted without reading return shape, failure modes, and call sites.

## 15. Utility Fast-Path Bypass

Preview, import, migration, debug, compatibility, cache, download, editor-link, and template routes skip the normal policy path because they were built for convenience.

## 16. Server/Client Boundary Collapse

Server-only data reaches client bundles, serialized props, public JSON, browser logs, generated files, analytics, prompt text, plugin config, or exported documents.

## 17. Route Exposure Drift

New route files become reachable by default with no central classification as public, authenticated, role-gated, webhook-only, internal, or disabled.

Report route exposure explicitly when a reachable route name implies non-user-facing or safe behavior but the route has sensitive effects. Common examples: `helper/delete-*`, `debug/*`, `setup/bootstrap`, `internal/*`, `cache/flush`, `preview/*`, `asset/sign`, `safe/export`, `template/*`, `demo/*`, and `test/*`. Do not hide these only inside broad authorization or side-effect findings; the exposure path is the bug.

## 18. Sanitization Fragmentation

Rich content is sanitized in one surface but not others: admin preview, public rendering, email, chat, PDF, export, search index, logs, or AI prompts.

## 19. Bootstrap Boundary Confusion

Setup, first-user, invitation, registration, import, or migration code creates privileged state without a one-time installation boundary or durable guard.

## 20. Risk Composition Failure

Small gaps combine into a real attack path: verbose errors plus missing rate limit plus public write plus expensive external call, or weak CORS plus cookie auth plus state mutation.

## 21. Malformed Input

Parsing and shape assumptions turn bad input into crashes, partial writes, unsafe rendering, or provider calls. Check JSON parsing, `request.json`, multipart/file uploads, CSV/PDF/XML/markdown processing, nested objects, content types, body size, arrays, enum values, dates, URLs, emails, and operations such as `.map`, `.toUpperCase`, `parse`, `render`, or file processors. If the same path returns stack traces or logs sensitive data, report that separately as Error And Log Disclosure.

## Related Drift: Policy Memory Failure

Security should not rely on reviewers and future developers remembering rules. Prefer centralized helpers, schemas, tests, route classification, and capability inventories.

## Mandatory Escape-Hatch Pass

Before finalizing a production review, explicitly check:

- naming-biased names: `safe`, `public`, `preview`, `helper`, `asset`, `template`, `demo`, `test`, `internal`, `lead`, `quote`, `sync`, `download`, `callback`;
- fail-open branches: missing Redis/cache/rate-limit provider, disabled integration, missing env, provider catch block, `return true`, `success: true`, fake success, default admin/demo access;
- env/config/examples: `.env*`, `*.example`, deployment config, local tool config, public client config, generated docs, and tests that may contain real secrets or unsafe defaults.
- malformed-input boundaries: JSON/body parsing, file/document parsing, unsafe shape assumptions, size/type validation, nested objects, and parser errors. Keep this distinct from error/log disclosure when both are present.

If one of these passes is outside the user-provided scope, state that limitation in the review.
