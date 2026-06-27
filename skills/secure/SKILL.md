---
name: secure
description: Security review skill for AI coding agents. Use for secure code review, production security audit, vulnerability review, appsec hardening, pre-commit security review, authentication, authorization, secrets, CORS, CSRF, webhooks, payments, uploads, signed URLs, multi-tenant security, AI/PDF processing, and whole-project security remediation across JavaScript/TypeScript, Python, Java/Kotlin, .NET/C#, Go, Ruby, PHP, Rust, SQL/ORM-heavy services, mobile backends, monorepos, APIs, server actions, backend services, admin/CRM tools, and security-review benchmarks. Includes token-efficient project scraping, capability inventory, fix/verify/rescan workflows, and benchmark-grade coverage reporting.
---

# Secure

Review code by capability, data flow, and invariants. Do not review by filename vibes. A route named `preview`, `public`, `lead`, `template`, `sync`, `helper`, or `asset` can still mutate state, spend money, expose files, call AI, or cross tenant boundaries.

## Operating Standard

Behave like a production security reviewer preparing the user to commit or ship. Findings must be concrete, reproducible from code evidence, and ordered by risk. Prefer a short, defensible review over a broad checklist with weak claims.

Do not edit files unless the user explicitly asks for fixes. For a review request, inspect and report.

The professional bar is evidence over breadth. A good review proves a small set of important risks from code. A weak review lists many generic concerns without showing the broken invariant.

For hardening requests, optimize for confirmed fixes and verification, not for theoretical completeness. Do not promise "100% secure"; report how many confirmed findings were fixed and what remains.

Benchmark fixture hard rule: if the project is a benchmark fixture, skill test, security-review evaluation, or intentionally vulnerable project, the final answer must include `Findings`, `Verification`, `Coverage`, and `Case Coverage`. If response space is tight, shorten finding prose first; never omit `Verification`, `Coverage`, or `Case Coverage`.

Benchmark footer contract: always reserve room and end benchmark outputs with this exact compact footer shape, even when there are many findings. Copy it after findings before sending the answer; fill unknown command data with `Not run`, not by omitting the section. Keep the footer to these five content lines plus headings; do not add extra verification bullets before `Case Coverage`:

```text
Verification
- <command or "Not run">: <one-line result>

Coverage
Reviewed <one-line scope/capabilities>. Not reviewed <one-line limits>.

Case Coverage
Summary: <detected>/<total> Detected, <partial> Partial, <missed> Missed, <out-of-scope> Out of scope.
- Partial/Missed/Out of scope: <list or "None">
```

If all standard cases are detected, the `Summary` plus `None` exception line is sufficient. Do not omit this footer to save space.

Benchmark budget rule: in benchmark or skill-test outputs, keep every finding to one compact line: `Severity: title. Evidence: file:line. Impact: short impact. Fix: short invariant-restoring fix.` Do not use verbose Markdown links when plain `file:line` fits. If output space is constrained, compress findings before the footer; never write a bare `Verification`, `Coverage`, or `Case Coverage` heading without its content.

Benchmark answer skeleton:

```text
Findings
<one compact line per finding>

Verification
- <command or "Not run">: <one-line result or reason>

Coverage
Reviewed <one-line scope and capability areas>. Not reviewed <one-line limits or "No major scoped areas left unreviewed">.

Case Coverage
Summary: <detected>/<total> Detected, <partial> Partial, <missed> Missed, <out-of-scope> Out of scope.
- Partial/Missed/Out of scope: <list or "None">
```

Do not send a benchmark answer that lacks this skeleton. If the answer is too long, reduce finding text until the skeleton fits.

Benchmark footer must be completed, not merely started. A final answer ending with `Case Coverage` or any footer heading without the next required line is invalid. If you have room for the heading, you must write at least:

```text
Case Coverage
Summary: 21/21 Detected, 0 Partial, 0 Missed, 0 Out of scope.
- Partial/Missed/Out of scope: None
```

When all 21 standard cases are detected, use that exact three-line `Case Coverage` block.

Before sending a benchmark final answer, perform this self-check and rewrite if any answer is "no":

- Does it start with `Findings`?
- Does every expected invariant have either an atomic finding or an explicit non-detected status?
- Does it include `Verification` with real commands run or `Not run`?
- Does it include `Coverage` and `Case Coverage` after findings?
- Does `Case Coverage` account for detected, partial, missed, and out-of-scope cases?
- Does `Case Coverage` include the `Summary:` line immediately after the heading?
- Does the answer avoid ending on an empty section heading?
- Would copying the answer into a benchmark grader show the skeleton fields present by exact heading?

## Setup

Before writing findings:

1. Confirm the requested review scope.
   - If the user gives a path, stay inside that path unless they explicitly widen scope.
   - If the user gives a project directory or says "whole project", "entire repo", "all files", "todo el proyecto", or equivalent, review the whole scoped project even if they also mention committing.
   - If the user gives a source subdirectory such as `src`, `app`, `api`, `server`, `backend`, or `packages/foo/src` while using project-level wording such as "project", "repo", "before commit", "ship", "production", or "todo", inspect that code path plus the nearest project root config/examples inside the same project. At minimum check package/framework markers, env examples, deployment config, middleware/auth config, and tests. Do not read sibling projects or parent answer keys.
   - If the user explicitly says "only this folder", "do not use other files", "solo esta carpeta", or provides a benchmark scope, stay inside that exact scope and state that env/config outside scope was not reviewed.
   - If the user asks for current repo without a path, inspect the current repo as the scope.
   - If the user explicitly asks for only the diff, changed files, PR, staged changes, or commit delta, prioritize changed files, then security-critical reachable code they depend on.
   - If scope is ambiguous, prefer the broader project review inside the current workspace rather than asking the user to choose a command.

2. Build a capability inventory.
   - For whole-project reviews, first run the bundled compact scraper unless the project is tiny or the environment cannot run Python:

     ```bash
     python <skill-dir>/scripts/project_scraper.py <project-path> --budget-chars 18000
     ```

     Use the review pack to choose files to read next. Do not report findings from the pack alone.
   - If the user asks for an explicit inventory, or if the scraper pack is too compressed, run the full static inventory:

     ```bash
     python <skill-dir>/scripts/inventory_scan.py <project-path> --format markdown
     ```

     Treat script output as leads, not findings. Follow the code before reporting.
   - Read [references/capability-inventory.md](references/capability-inventory.md) for medium/large projects, admin systems, public APIs, upload/storage flows, AI/PDF/document processing, payments, multi-tenant code, or benchmark fixtures.
   - Use the inventory to decide what to inspect. Do not stop at obvious names.

3. Run a pattern second pass when risk is non-trivial.
   - Read [references/pattern-taxonomy.md](references/pattern-taxonomy.md) when the project has more than a few files, when the first pass finds only one obvious issue, or when the review may be affected by naming/capability bias.
   - Always run an explicit escape-hatch pass before finalizing a production review: naming bias, fail-open behavior, env/config/examples, route exposure, and public side effects. These are common misses even after a strong first pass.
   - For route exposure, explicitly inspect sensitive routes whose names make them look non-production or harmless: `helper`, `debug`, `setup`, `bootstrap`, `internal`, `preview`, `public`, `asset`, `safe`, `template`, `test`, `demo`, `cache`, `flush`, `export`, and `download`. If one is reachable and mutates, deletes, exports, signs, creates admins, reveals private data, or spends resources without the required guard, report it as route exposure or naming bias, not only as a generic auth issue.

4. Load framework and release checks for the relevant stack.
   - Read [references/framework-and-release-checks.md](references/framework-and-release-checks.md) for whole-project reviews, production-readiness reviews, unfamiliar frameworks, storage/upload flows, AI/document processing, payments, or webhooks.
   - Use only the sections that match the project. Do not paste the checklist into the final answer.

5. Load language-specific checks when needed.
   - Read [references/language-stack-checks.md](references/language-stack-checks.md) for non-JS projects, multi-language repositories, unfamiliar frameworks, ORM-heavy services, or when the scraper identifies Java, Kotlin, C#, Python, Go, Ruby, PHP, Rust, Elixir, mobile/backend, or SQL-heavy code.
   - Translate invariants across languages. `@Authorize`, `permission_classes`, middleware, policies, guards, and filters are all just guard mechanisms; verify they dominate the sink.

6. Use the output contract.
   - Read [references/review-output.md](references/review-output.md) before the final response for review, audit, compare, or benchmark tasks.

7. Load auto-hardening rules when edits are requested.
   - Read [references/auto-hardening.md](references/auto-hardening.md) when the user asks to fix, harden, secure, prepare to ship, make production-ready, "arregla todo", "déjalo listo para subir", or similar.

## Commands

If the user invokes a sub-command, follow the matching route. If no sub-command is present, infer intent from natural language.

Default behavior must be user-friendly: when the user asks to "review this project", "check this repo", "audit this app", or gives a project folder with review language, perform a whole-project security review of that scope. When the user asks to "secure this project", "fix the security problems", "make this production ready", "prepare to ship", "déjalo listo para subir", or invokes `$secure <project-path>` without more detail, use `harden-all` behavior. Do not expect the user to know command names.

| Command | Use |
|---|---|
| `review [path or diff]` | Default security review. If given a project folder, review the whole project. If the user explicitly says diff, changed files, PR, or before commit, prioritize changed files and their reachable security-critical dependencies. Findings first, no code edits. |
| `audit [path]` | Explicit broader production readiness audit across routes, config, auth, storage, logs, and operational failure modes. Use the same depth as whole-project `review`, with more emphasis on deployment readiness. |
| `harden [target]` | Implement fixes for known or newly confirmed findings. Keep changes scoped and verify with tests or focused checks. |
| `harden-all [path]` | Whole-project scan, confirm, fix, verify, rescan, and iterate. Target zero confirmed Critical/High findings in scope and maximum safe Medium coverage. |
| `secure [path]` | Alias for `harden-all`; use when the user says to secure, fix everything, or prepare for production. |
| `threat-model [feature]` | Map actors, assets, trust boundaries, sensitive sinks, invariants, abuse cases, and required controls. |
| `compare [reviews or outputs]` | Evaluate review quality, missed findings, severity drift, naming bias, and evidence quality. |
| `inventory [path]` | Produce only the sensitive capability inventory and recommended inspection order. |
| `scrape [path]` | Produce a compact low-token review pack only: top risky files, routes, possible secrets, capability index, and inspection plan. |

## Review Workflow

1. Establish baseline.
   - Inspect file tree, package/framework markers, route structure, env/config files, and changed files if available.
   - Identify framework security defaults that matter: cookies, server actions, API routes, middleware, CORS, CSRF, request body limits, runtime boundaries.
   - Identify all languages/stacks in scope before assuming route, auth, test, or build conventions.
   - For Git repos, inspect status and tracked/untracked security-relevant config, but never leave the requested scope.
   - For large projects, use the compact scraper output before reading source files manually.

2. Inventory sensitive capabilities.
   - Map routes/actions/services that authenticate, authorize, mutate, publish, delete, transfer, upload, sign URLs, send notifications, call external APIs, call AI/PDF/document tools, handle money, return debug info, or accept public writes.
   - Record the guard expected for each sink: auth, role, tenant, ownership, state transition, schema validation, rate limit, CSRF/CORS, storage policy, timeout, audit log.

3. Follow data to the sink.
   - Read route handler plus called helpers. Do not trust helper names.
   - Verify the guard dominates the sink on every path, including fallback, error, compatibility, preview, and disabled-integration paths.
   - Check object-level scope at the query/update/delete/signing boundary, not only in UI or list filters.

4. Test the invariant mentally, then with commands when cheap.
   - Ask what a malicious user can control: headers, cookies, IDs, tenant IDs, object keys, URLs, metadata, status fields, roles, files, prompt text, callback URLs.
   - Look for mass assignment, confused-deputy flows, fail-open behavior, direct object references, stale compatibility paths, and public endpoints that spend private resources.
   - Specifically search for fail-open and fake-success branches: `failOpen`, `demo`, `mock`, `enabled`, `disabled`, `fallback`, `default`, missing Redis/cache/rate-limit providers, missing env vars, disabled integrations, provider catch blocks, and `return true` or success responses in error paths.
   - Specifically search for naming bias: routes/helpers/files containing `public`, `preview`, `helper`, `asset`, `safe`, `demo`, `test`, `internal`, `lead`, `quote`, `template`, `sync`, `download`, or `callback`. Review their behavior by side effect and authority, not name.
   - Specifically separate malformed-input findings from error-disclosure findings when both exist. Parsing crashes, unchecked shape assumptions, oversized bodies, invalid content types, unsafe file/document parsing, and operations like `JSON.parse`, `request.json`, `.map`, `.toUpperCase`, `parse`, `render`, or upload processors without validation are validation issues. Returning `error.message`, `error.stack`, provider payloads, headers, or PII is a separate logging/error disclosure issue.
   - Run available tests or typechecks when feasible; do not invent test success.

5. Finalize findings.
   - Lead with the most important findings.
   - Include exact file references and line numbers when possible.
   - Explain impact in production terms.
   - Give the smallest fix that restores the invariant.
   - State verification limits and residual risk.
   - For whole-project or production reviews, mention whether naming-bias, fail-open, and env/config/example passes were covered. If one was out of scope, say so.
   - Reconcile findings with coverage before finalizing. If you say a category was reviewed, confirmed issues in that category must appear as findings. Do not hide malformed-input validation issues, naming-bias issues, fail-open branches, or secret/config leaks only in Coverage.
   - For benchmark fixtures, skill tests, security-review evaluations, or intentionally vulnerable projects, use atomic findings by broken invariant. Do not combine separate expected cases into one finding. Split authentication trust, authorization, tenant scope, owner scope, mass assignment, state transitions, route exposure, side effects, fail-open, visibility, secrets/examples, CORS/CSRF, rate limits, malformed input, error/log disclosure, upload boundary, signed URL scope, AI/document processing, payments, webhooks, and naming bias into separate findings when evidence exists.
   - For normal production reviews, grouping is allowed only when the same exploit path, same sink, same impact, and same fix restore the same invariant. Do not combine unrelated invariants such as CORS/CSRF, malformed input, and error disclosure into one finding just because they share a file or route.
   - For benchmark fixtures, skill tests, security-review evaluations, or intentionally vulnerable projects, the final response is incomplete without `Case Coverage`. Include each expected case as `Detected`, `Partial`, `Missed`, or `Out of scope`. If the project does not provide case names, use the standard 21-case Secure set from [references/review-output.md](references/review-output.md).
   - For benchmark fixtures, do not spend the entire response budget on findings. Reserve room for `Verification`, `Coverage`, and `Case Coverage`; these sections are part of the required output, not optional cleanup. If the answer would be long, shorten each finding first, then use the compact `Case Coverage` summary.
   - Treat naming bias as its own benchmark invariant. If routes such as `helper`, `safe`, `public`, or `preview` carry sensitive behavior, include either a separate Naming Bias finding or mark it explicitly in `Case Coverage`; do not rely on route names appearing incidentally in other findings.

## Token Discipline For Large Projects

Do not load an entire repository into context. Scan locally, then read selectively.

Use this order:

1. Run `project_scraper.py` with a bounded output budget.
2. Read the top-risk routes, policy helpers, config files, and sink implementations from the pack.
3. Follow only the call chains needed to prove or disprove the highest-risk invariants.
4. Run focused searches for missed capability classes.
5. Report coverage honestly.

Recommended budgets:

- small project: `--budget-chars 12000`;
- normal project: `--budget-chars 18000`;
- large monorepo: `--budget-chars 24000 --top-files 50`, then inspect by package.

The scraper is allowed to read many files because it runs locally and emits a compact summary. The final review still requires reading actual source around each suspected finding.

## Minimum Coverage For Whole-Project Review

For a project folder review, inspect at least:

- route/action/API entry points;
- auth/session and authorization helpers;
- database query/update/delete boundaries for direct object access;
- storage/upload/signed URL/file rendering paths;
- public forms, webhooks, contact/lead/quote endpoints, and other unauthenticated writes;
- environment/config/defaults, example env files, deployment config, and local tool config under the scoped project;
- logging/error handling patterns;
- malformed input and parser boundaries, including JSON, multipart, CSV, PDF, XML, markdown, URLs, nested objects, size limits, content types, and shape assumptions;
- rate limits, quotas, and expensive external-call paths;
- tests or schemas that are supposed to enforce security invariants.
- naming-biased routes/helpers such as `safe`, `public`, `preview`, `helper`, `asset`, `template`, `demo`, `test`, `internal`, `lead`, `quote`, `sync`, `download`, and `callback`;
- fail-open/fake-success branches in auth, authorization, rate limit, storage, webhooks, payment, AI/document processing, and external integrations.

If the project is too large to inspect all of this in one pass, say exactly which categories were reviewed and which remain.

## Severity Rules

Use `Critical` when exploitation can directly produce one of these outcomes:

- unauthenticated privileged mutation or admin action;
- cross-tenant/private data access or private file exposure;
- arbitrary object deletion/write/signing across trust boundaries;
- live secret committed or exposed in reachable code/config;
- direct bypass of role, ownership, approval, payment, publish, or tenant isolation.

Use `High` for:

- authenticated but unauthorized writes or reads;
- mass assignment of policy fields such as `role`, `tenantId`, `ownerId`, `status`, `visibility`, `approvedAt`, `deletedAt`, `price`, or `plan`;
- public write endpoints without meaningful abuse controls;
- signed URL, upload, webhook, or callback boundary errors;
- serious fail-open behavior in auth, rate limiting, storage, payments, or external calls.

Use `Medium` for:

- weak validation or malformed input causing 500s;
- excessive error disclosure or logs with PII/internal details;
- incomplete CORS/CSRF controls where exploitability depends on deployment/session details;
- missing timeouts, retries, or resource limits;
- security-relevant inconsistency that needs another condition to become exploitable.

Use `Low` for:

- hardening gaps with limited direct impact;
- missing tests around security invariants;
- documentation or operational clarity issues that could cause future drift.

Do not inflate severity without an exploit path. Do not downplay a finding because the code is a fixture, demo, or internal route if the user asked for production/security review.

## Absolute Guardrails

- Do not mark code safe from route names, comments, UI hiding, or optimistic helper names.
- Do not assume localhost, demo headers, example env files, or disabled integrations are safe in production.
- Do not finish a production review without checking fail-open branches and naming-biased paths, or clearly saying they were out of scope.
- Do not merge malformed input validation failures into logging/error disclosure when each has separate code evidence. Report both or explicitly say one is only a consequence of the other.
- Do not treat authentication as authorization.
- Do not treat tenant filtering on list endpoints as proof that direct object endpoints are scoped.
- Do not report generic best practices without code evidence.
- Do not bury a secret leak, auth bypass, cross-tenant issue, or arbitrary storage operation under lower-priority findings.
- Do not keep reviewing unrelated folders when the user provided an explicit scope.

## Output Contract

For review/audit tasks, final output must use this order:

1. Findings first, ordered by severity.
2. Open questions or assumptions only if they affect exploitability.
3. Verification: commands run and whether they passed.
4. Residual risk or unreviewed areas.

For benchmark fixtures or skill tests, include this order instead:

1. Findings first, ordered by severity.
2. Verification.
3. Coverage.
4. Case Coverage with `Detected`, `Partial`, `Missed`, or `Out of scope` for each case.
5. Residual risk or unreviewed areas.

Each finding should include:

- severity and concise title;
- file/function/route;
- evidence from code;
- production impact;
- recommended fix.

If there are no findings, say that clearly and still mention verification limits.

Do not include the raw static inventory in the final answer unless the user asked for `inventory`. Use it to drive inspection.

## Fixing Mode

When the user asks to fix or harden:

1. Read [references/auto-hardening.md](references/auto-hardening.md).
2. Preserve the discovered invariant in code, not only the local symptom.
3. Prefer centralized authorization, validation, and storage-policy helpers over route-local patches.
4. Add focused tests for the exploit path when the project has tests.
5. Verify with the narrowest meaningful command first, then broader checks if available.
6. Re-run the scraper or focused searches after fixes to catch the same failure class elsewhere.
7. Iterate until confirmed Critical/High findings are fixed, verification blocks progress, or further fixes require product/external decisions.
8. Summarize changed files, fixed findings, remaining findings, blockers, verification, and fix coverage.

For "fix everything" requests, use `harden-all` behavior even if the user does not name that command. Do not stop after the first patch if other confirmed Critical/High findings remain.
