---
name: secure-code-review
description: Secure alias for secure code review and production appsec review across JavaScript, TypeScript, Python, Java, .NET, Go, Ruby, PHP, Rust, SQL-heavy services, APIs, server actions, monorepos, admin tools, CRM systems, mobile backends, AI-generated codebases, and vibe-coded apps. Use before commit or production to find auth, authorization, tenant, secrets, CORS, CSRF, webhook, payment, upload, storage, signed URL, input validation, and logging issues.
---

# Secure Code Review

Perform a production-focused secure code review.

Review the codebase for exploitable behavior, not checklist compliance. Prefer a small number of proven findings over a long list of weak guesses.

## Inspection Order

1. Read project structure, package scripts, framework conventions, route files, server actions, middleware, auth/session helpers, config, env examples, and tests.
2. Identify sensitive capabilities:
   - auth and role creation;
   - object reads/writes/deletes;
   - tenant and owner boundaries;
   - public writes and expensive side effects;
   - file upload, preview, storage, and signed URL flows;
   - AI/PDF/document/browser processing;
   - payment, webhook, subscription, price, plan, balance, and quota flows.
3. Follow untrusted inputs from params, body, query, headers, cookies, files, webhooks, and callbacks to database, storage, network, email, AI, payment, and logging sinks.
4. Confirm whether auth, authorization, object scope, schema validation, rate limits, CSRF/CORS, timeouts, and error handling dominate the sink.

## Report

Findings first, ordered by severity.

Include:

- `Critical` for auth bypass, unauthenticated privileged mutation, cross-tenant/private data access, arbitrary storage signing/deletion, live secret exposure, or direct payment/webhook trust failures.
- `High` for unauthorized reads/writes, mass assignment of policy fields, public abuse paths, signed URL/upload ownership errors, or serious fail-open behavior.
- `Medium` for malformed input DoS, stack trace/provider leakage, incomplete CORS/CSRF, missing timeouts, or security drift that needs another condition to exploit.

End with verification commands and residual risk.

