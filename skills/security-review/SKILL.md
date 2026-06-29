---
name: security-review
description: Search-friendly Secure alias for production security review, secure code review, vulnerability review, appsec audit, pre-commit review, authentication and authorization checks, tenant isolation, secrets, CORS, CSRF, webhooks, payments, uploads, signed URLs, public endpoints, AI-generated code, and vibe-coded applications. Use when the user asks to review a project before commit, before shipping, or before production.
---

# Security Review

Act as the Secure production security reviewer.

Review by capability, data flow, and broken invariants, not by filenames or route names. A route called `preview`, `helper`, `public`, `safe`, `asset`, `template`, or `sync` can still mutate state, spend money, leak private data, or cross tenant boundaries.

## Workflow

1. Confirm the exact project scope and inspect only that scope.
2. Start with `git status`, package scripts, framework, routes/actions/API entry points, auth helpers, config, env examples, and tests.
3. Build a sensitive capability inventory:
   - auth/session creation and role assignment;
   - admin, CRM, dashboard, tenant, owner, and organization boundaries;
   - create/update/delete/publish/archive/approve/transfer flows;
   - uploads, signed URLs, file previews, storage keys, PDF/document/AI processing;
   - public forms, leads, contact, quote, callbacks, webhooks, and expensive endpoints;
   - payment, plan, price, subscription, balance, credit, quota, and finance code;
   - CORS, CSRF, rate limits, logging, error handling, secrets, and fail-open branches.
4. Follow user-controlled input to sensitive sinks. Verify the guard dominates the sink on every path.
5. Report only findings supported by code evidence.

## Findings

Lead with production/security risks, ordered by severity. Each finding must include:

- severity and concise title;
- file/function/route evidence;
- production impact;
- recommended fix.

Prioritize:

- forged auth or trusted client identity;
- authentication without authorization;
- cross-tenant or cross-owner direct object access;
- mass assignment into policy fields;
- unsafe state transitions;
- public route exposure;
- side effects reachable without proper checks;
- fail-open behavior;
- private visibility leaks;
- secrets and unsafe examples;
- wildcard credentialed CORS or missing CSRF on browser mutations;
- missing rate limits on public/expensive endpoints;
- malformed input and unbounded parsing;
- stack traces, sensitive logs, and provider payload leakage;
- upload/storage/signed URL ownership errors;
- AI/PDF/document processing without auth, quotas, limits, or sandboxing;
- payment/webhook authenticity failures;
- naming bias hiding sensitive behavior.

## Verification

Run focused tests, typecheck, lint, build, or targeted commands when feasible. Do not invent successful verification.

Final output order:

1. Findings first.
2. Open questions or assumptions only if they affect exploitability.
3. Verification.
4. Residual risk or unreviewed areas.

