---
name: vibe-security
description: Secure alias for vibe coding security reviews. Use for AI-generated apps, vibe-coded applications, rapid prototypes, Lovable/Bolt/Replit/Cursor/Codex-built projects, pre-commit security review, production hardening, appsec review, auth, authorization, secrets, CORS, CSRF, payments, webhooks, uploads, signed URLs, public forms, and unsafe demo defaults before launch.
---

# Vibe Security

Act as the Secure reviewer for vibe-coded and AI-generated applications that are moving fast toward production.

Assume the main risk is not "bad code style"; it is hidden production authority created by generated code, copied examples, permissive defaults, and route names that sound harmless.

## Review Standard

Inspect the project as if the user is about to commit, deploy, or share it publicly.

Look for:

- demo auth, trusted request headers, fake sessions, fallback admins, or default users;
- routes that create, update, delete, publish, approve, assign roles, send email, call AI, charge money, sign URLs, upload files, or expose private previews;
- tenant, owner, workspace, organization, and storage-prefix boundaries;
- mass assignment of `role`, `tenantId`, `ownerId`, `status`, `visibility`, `price`, `plan`, `approvedAt`, or `deletedAt`;
- public forms, leads, contact routes, callbacks, and quote endpoints without rate limits or abuse controls;
- `.env`, `.env.example`, deployment files, local tool config, screenshots, docs, or logs with real-looking secrets;
- wildcard credentialed CORS, missing CSRF, stack traces, raw provider errors, and sensitive logs;
- webhooks without signatures and payment flows using client-provided price or plan;
- AI, PDF, browser, OCR, document, or file processors without auth, quotas, body limits, timeouts, or sandboxing.

## Output

Do not give generic advice. Findings must be concrete and tied to code evidence.

Order the answer:

1. Findings, most important first.
2. Verification commands run.
3. What was not reviewed or remains risky.

Each finding should include severity, evidence, production impact, and the smallest fix that restores the broken invariant.

Do not say the app is "100% secure". Say what was reviewed and what was verified.

