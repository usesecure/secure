# Framework And Release Checks

Load this reference when reviewing a whole project, production release, or unfamiliar stack. Use only the relevant sections.

For non-JavaScript stacks, also load [language-stack-checks.md](language-stack-checks.md).

## Universal Release Gates

Check these before saying a project is ready to ship:

- no live secrets in tracked files, local tool config, examples, logs, screenshots, generated docs, or committed deployment files;
- environment defaults do not enable demo auth, fake success, permissive CORS, disabled rate limits, public buckets, or broad admin access;
- public endpoints have explicit route classification and abuse controls;
- privileged mutations use centralized authorization and object-level scope;
- logs and error responses do not expose PII, provider responses, stack traces, storage keys, tokens, or internal URLs;
- dependency and type/test checks were attempted, or blockers are stated clearly.

## Next.js / React Server Apps

Inspect:

- `app/**/route.ts`, `pages/api/**`, `middleware.ts`, server actions, and auth helpers;
- cookie/session settings, SameSite behavior, CSRF controls on browser-cookie mutations;
- server-only values crossing into client components, serialized props, public JSON, or build-time env exposure;
- route handlers that return `error.message` or provider payloads;
- direct object endpoints that skip tenant scope present in list endpoints;
- `revalidatePath`, cache invalidation, redirects, image/file proxying, and signed URL generation.

Common production failures:

- trusting demo headers or client-provided role/tenant values;
- assuming UI hiding protects API routes;
- using `NEXT_PUBLIC_*` for secrets or provider configuration that should remain server-only;
- parsing `request.json()` without size/type validation and returning 500 on malformed input;
- public form endpoints calling email/AI/PDF providers without rate limits.

## Node / Express / API Services

Inspect:

- middleware ordering for auth, body parsing, CORS, rate limits, and error handlers;
- routers mounted under broad prefixes such as `/api`, `/internal`, `/admin`, `/public`;
- object ID lookups, update/delete calls, and query builders for tenant/owner scope;
- file upload middleware, temp file cleanup, MIME validation, and size limits;
- outbound HTTP calls, retries, timeouts, and SSRF-relevant URL inputs.

Common production failures:

- auth middleware missing on one router;
- `...req.body` mass assignment into ORM updates;
- route-level CORS that allows credentialed browser calls from unexpected origins;
- operational endpoints reachable from the public internet.

## Server Framework Equivalents

Apply the same review model across stacks:

- Next/Express route handlers map to Spring controllers, ASP.NET controllers/Minimal APIs, Django/Flask/FastAPI views, Rails controllers, Laravel controllers, Go handlers, and Rust handlers.
- Middleware maps to filters, interceptors, guards, dependencies, route groups, layers, and before actions.
- Permission helpers map to policies, gates, voters, annotations, decorators, claims checks, and permission classes.
- ORM updates map to EF Core `SaveChanges`, JPA repositories, Django ORM `.save()`, ActiveRecord `update`, Eloquent `create/update`, GORM/SQLx/Diesel calls.

The question is always: does the guard dominate the sink with the right object scope?

## Multi-Tenant SaaS / Admin / CRM

Inspect:

- tenant, organization, workspace, account, collection, and owner boundaries on every direct object route;
- admin impersonation, transfer, invite, role assignment, plan changes, export, delete, and restore flows;
- invariants such as cannot delete last admin, cannot approve own change, cannot publish unreviewed private content;
- search, autocomplete, export, audit log, notification, and webhook paths for cross-tenant leakage.

Common production failures:

- list endpoints are scoped but detail/update/delete endpoints are not;
- admins are global when the product expects tenant admins;
- metadata or filters allow querying across tenants;
- background jobs run with broader scope than the initiating user.

## Storage / Upload / Signed URLs

Inspect:

- how object keys are derived, normalized, stored, signed, deleted, and exposed;
- whether keys include tenant/owner prefixes and are verified against DB ownership before signing/deleting;
- upload MIME/type detection, extension handling, size limits, malware scanning expectations, and transform pipelines;
- public/private bucket policies and default ACL behavior;
- whether public URLs, redirects, or previews leak private keys.

Common production failures:

- signing arbitrary client-provided keys;
- deriving delete keys from URLs instead of DB records;
- allowing path traversal or prefix confusion in object keys;
- treating image/PDF metadata as trusted.

## AI / PDF / Document Processing

Inspect:

- public endpoints that call paid models, browser automation, OCR, PDF renderers, or document parsers;
- prompt/input boundaries, uploaded file size/page count limits, timeouts, and queue isolation;
- whether document text, AI output, or prompt content is treated as user authorization or system instruction;
- generated PDF/HTML/email rendering for XSS, SSRF, local file access, or template injection;
- logs and traces for prompt, document, PII, and provider payload leakage.

Common production failures:

- no rate limit or quota on expensive inference/rendering;
- rendering untrusted HTML with local/network access enabled;
- leaking prompts or parsed documents in errors/logs;
- accepting AI output as a direct policy decision without server-side validation.

## Payments / Finance / Quotas

Inspect:

- server-side source of truth for price, amount, plan, quota, discount, currency, tax, and payment status;
- webhook signature verification and idempotency;
- client-provided amounts or plan IDs;
- refunds, credits, supplier costs, and balance mutations;
- rounding, currency conversion, and environment split between test/live providers.

Common production failures:

- trusting client-provided price/plan/quota;
- webhook route accepts unsigned events;
- processing duplicate webhook events;
- returning sensitive provider objects to clients.

## Webhooks / Integrations

Inspect:

- signature verification, replay prevention, timestamp tolerance, idempotency, and provider-specific event source;
- route exposure, method restrictions, body parser compatibility, and logging;
- failure behavior and retry safety;
- whether integration disablement creates fake success or skipped authorization.

Common production failures:

- webhook accepts any POST with a plausible event shape;
- raw body needed for signatures is consumed before verification;
- duplicate delivery creates duplicate state changes;
- provider errors are returned or logged verbatim.
