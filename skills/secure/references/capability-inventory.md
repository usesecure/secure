# Capability Inventory

Build this inventory before finalizing reviews of medium/large projects, admin systems, public APIs, storage/upload flows, AI/document processing, finance/payment code, or benchmark fixtures.

The inventory is not usually user-facing. Use it to choose what to inspect and to avoid naming bias.

For whole-project reviews, start with the compact scraper:

```bash
python <skill-dir>/scripts/project_scraper.py <project-path> --budget-chars 18000
```

Use it as a token-efficient review pack: top files, routes, possible secrets, capability index, and inspection order.

For deeper inventory-only tasks, use the full inventory script:

```bash
python <skill-dir>/scripts/inventory_scan.py <project-path> --format markdown
```

Script output is a map of leads. It is not proof of vulnerability.

## Inventory Table

Track these fields mentally or in notes:

| Surface | Capability | User-controlled inputs | Sensitive sink | Required guard | Evidence checked |
|---|---|---|---|---|---|
| route/action/helper | write/sign/send/delete/etc. | IDs, headers, body, files, URL params | DB, S3, email, AI, payment | auth, role, tenant, owner, validation, rate limit | files/functions read |

When returning an `inventory` command to the user, group by capability and recommended inspection order. Do not include every low-signal keyword hit.

## Sensitive Capability Categories

Prioritize code that can:

- create, update, delete, publish, archive, approve, restore, transfer, import, export, or duplicate records;
- assign roles, owners, tenants, reviewers, permissions, plans, prices, status, visibility, feature flags, or approval timestamps;
- upload, transform, render, parse, download, sign, proxy, or delete files;
- derive object storage keys from user-controlled URLs, paths, names, metadata, or public IDs;
- return signed URLs, redirects, file previews, public links, schemas, metadata, debug data, stack traces, logs, or provider responses;
- send email, SMS, chat, webhook, notification, calendar invite, support message, or operational alert;
- invalidate cache, flush Redis, enqueue jobs, trigger background workflows, revalidate pages, or reset state;
- call AI models, browser automation, PDF renderers, document parsers, OCR, image tools, or external APIs;
- process prices, currencies, taxes, discounts, balances, credits, quotas, subscriptions, supplier costs, or payment states;
- accept public writes such as leads, contact forms, quote requests, callback requests, tracking events, waitlists, or file submissions.

## Required Checks Per Capability

For each sensitive sink, verify:

- authentication happens before private object-specific error details;
- authorization checks role plus object scope where needed;
- tenant, owner, organization, workspace, collection, and storage-prefix constraints are enforced at query/update/delete/signing time;
- state transitions preserve invariants such as draft -> review -> published, cannot delete last admin, cannot approve own request, cannot restore deleted private content publicly;
- policy fields are not mass-assignable from normal user payloads;
- schema validation rejects malformed types, oversized values, unknown policy fields, nested metadata abuse, and invalid enum values;
- rate limits, quotas, and abuse controls exist on public or expensive endpoints;
- CORS/CSRF/session behavior is correct for browser-reachable cookie-authenticated routes;
- external calls have timeouts, failure handling, and do not fail open;
- logs, errors, analytics, and audit trails avoid secrets and unnecessary PII;
- privileged mutations create durable audit events where the product needs accountability.

## Search Hints

Use searches as leads, then read surrounding code and helper definitions.

```bash
rg -n "delete|remove|destroy|archive|restore|publish|approve|transfer|assign|role|tenantId|ownerId|status|visibility|approvedAt|deletedAt|reviewerId|plan|price|amount"
rg -n "signed|presign|createSigned|S3|bucket|upload|download|asset|file|metadata|publicUrl|redirect|webhook|email|sms|chat|notify"
rg -n "process.env|fallback|enabled|success|isAdmin|canAccess|public|private|preview|debug|error.message|console\\.error|rateLimit|cors|csrf"
rg -n "openai|anthropic|ai|pdf|chromium|puppeteer|playwright|ocr|parse|render|fetch\\("
```

For Next.js projects, include:

```bash
rg --files | rg "app/.*/route\\.(ts|js)|pages/api|middleware\\.(ts|js)|server-actions|actions"
```

## Large-Project Second Pass

Before finalizing, ask:

- Which route looks harmless but has an expensive or privileged side effect?
- Which helper name was trusted before its contract was read?
- Which direct-object endpoint lacks the tenant/owner filter present in list endpoints?
- Which fallback path allows access when Redis, env vars, auth providers, storage, or external APIs are missing?
- Which public endpoint can be abused for spam, scraping, AI spend, file processing, or operational noise?
- Which output leaks storage keys, provider errors, internal IDs, private metadata, or environment assumptions?
