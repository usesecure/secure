# Review Output

Use this contract for user-facing production and security reviews.

## Findings First

Start with findings. Do not lead with a long narrative, methodology recap, or praise.

Order findings by real production risk:

1. direct exploitability and blast radius;
2. trust-boundary violation;
3. likelihood in deployed configuration;
4. ease of remediation.

## Required Finding Shape

Each finding must contain:

- severity: `Critical`, `High`, `Medium`, or `Low`;
- concise title naming the failure, not the symptom;
- affected file, route, function, or config;
- evidence from code, with line references when available;
- impact in production terms;
- recommended fix that restores the broken invariant.

Use atomic findings when the broken invariants differ. Separate findings are expected for:

- authorization vs tenant/object scope;
- mass assignment vs state-transition validation;
- upload ownership vs signed URL scope;
- CORS/CSRF vs malformed input vs error/log disclosure;
- public side effects vs rate-limit/quota abuse when both are independently exploitable;
- secret exposure in a reachable route vs unsafe secrets/defaults in examples or config.

Grouping is acceptable only when the same exploit path, same sink, same impact, and same fix restore the invariant. If grouping would make a benchmark case count ambiguous, split it.

Good:

```text
Critical: publish endpoint lets any authenticated user update cross-tenant entries.
Evidence: `publishEntry` looks up by `id` and `collectionSlug` only, then updates the record without calling the permission helper or filtering by `session.user.tenantId`.
Impact: a user who knows another tenant's entry ID can publish, transfer, or delete content across tenants.
Fix: scope the lookup/update by tenant, call the canonical permission helper before mutation, and reject policy fields from normal edit payloads.
```

Weak:

```text
Add more auth checks to the publish route.
```

## Evidence Rules

- Prefer exact code paths over broad guesses.
- If a helper is suspicious, read its implementation before reporting.
- If exploitability depends on deployment configuration, say what is unknown.
- If the code is a fixture or demo but the user asked for production review, evaluate the behavior as production behavior.
- Do not call something vulnerable only because a keyword appears in search output.
- Do not mention a sensitive category in `Coverage` as reviewed if confirmed evidence was found but no finding or explicit no-finding note exists for that category.
- Keep malformed-input validation separate from error/log disclosure when there is separate evidence. A route that both crashes on bad input and returns `error.stack` has two findings or one combined finding with two clearly named failures; do not report only the stack leak and bury validation in coverage.

## Coverage Integrity Checklist

Before finalizing, reconcile coverage against findings:

- If `malformed input`, parser boundaries, body parsing, uploads, document parsing, or shape validation were reviewed, include a finding for unchecked malformed input when evidence exists, such as `JSON.parse`, `request.json`, `.map`, `.toUpperCase`, file/document parsing, missing size/type checks, or parser exceptions that can be triggered by user input.
- If `logging`, `errors`, or observability were reviewed, include a separate finding when responses/logs expose `error.message`, `error.stack`, headers, provider payloads, PII, tokens, storage keys, or internal URLs.
- If `CORS` or `CSRF` was reviewed, include a separate finding when browser-reachable mutating routes use credentialed wildcard CORS, trust spoofable auth headers, lack CSRF protection, or allow cross-origin state mutation.
- If `naming bias` was reviewed, name the biased route or helper, such as `safe`, `public`, `preview`, `helper`, or `asset`, in the finding or coverage.
- If `fail-open` was reviewed, name the exact branch, such as missing Redis, disabled provider, missing env, `return true`, `success: true`, or fake success.
- If a reviewed category has no finding, say `No confirmed issue found for <category>` only when source evidence was actually checked.

## No-Finding Output

If no issues are found, say so directly:

```text
No production/security blockers found in the reviewed scope.
```

Then include verification and residual risk. Do not imply exhaustive safety if only a small scope was reviewed.

## Final Sections

After findings, include only the sections that add signal:

- `Open Questions`: assumptions that materially affect severity or exploitability.
- `Verification`: commands run, pass/fail, and notable blockers.
- `Coverage`: sensitive areas actually inspected when the user asked for a whole-project review.
- `Residual Risk`: important areas not reviewed or not decidable from available context.
- `Remediation Order`: top 2-5 fixes when there are multiple findings.

For whole-project reviews, `Coverage` should be concise and concrete:

```text
Coverage: inspected API routes, auth/session helpers, upload/storage paths, public form endpoints, env/config files, and rate-limit helpers. Did not review generated build output or third-party dependencies.
```

Do not list every file. Mention capability areas.

Never use `Coverage` to compensate for a missed finding. Coverage says what was inspected; findings say what was broken.

## Scrape Output

For `scrape [path]`, return a compact review pack, not security findings:

- scope and files scanned;
- suggested review plan;
- possible secrets;
- route/action entry points;
- highest-signal files with minimal snippets;
- capability index.

Always include that scraper output is leads only and source must be read before reporting findings.

## Hardening Output

For `harden`, `harden-all`, `secure`, or "fix everything" requests, lead with outcome, not findings.

Include:

- changed files;
- confirmed findings fixed;
- confirmed findings remaining;
- blocked items;
- verification commands and results;
- fix coverage from confirmed findings only.

Good:

```text
Fixed 6 confirmed security issues: 2 Critical, 3 High, 1 Medium.
Fix coverage: 5/5 confirmed Critical/High fixed, 1/3 Medium fixed, 2 Medium deferred because they require product decisions.
Verification: typecheck and targeted auth tests pass.
```

Do not say "100% secure". The strongest acceptable claim is scoped:

```text
No confirmed Critical/High findings remain in the reviewed scope after this pass.
```

If secrets were exposed, say code cleanup is not enough:

```text
Removed the committed secret from tracked files. The credential still needs external rotation because it was already exposed.
```

## Benchmark Or Comparison Output

When comparing reviews or evaluating a security-review benchmark, report:

- main bug detected or missed;
- severity correctness;
- whether file names biased the inspection path;
- sensitive capabilities skipped;
- evidence quality;
- whether proposed fixes restore the invariant or patch only one route.

For benchmark fixtures, use one finding per expected invariant even if a concise production review would group them. This makes missed findings, severity drift, and naming-bias failures measurable.

When the reviewed project is a benchmark fixture, skill test, intentionally vulnerable project, or security-review evaluation, add a concise `Case Coverage` section after `Verification` or `Coverage`. It must map the reviewed cases to `Detected`, `Partial`, `Missed`, or `Out of scope`. Use the project's available case names when known; otherwise use this standard set:

- Authentication Trust
- Authorization Dominance
- Tenant Boundary
- Owner Scope
- Mass Assignment
- State Transition Invariants
- Route Exposure
- Side Effect Reachability
- Fail-open Behavior
- Visibility Rules
- Secrets and Unsafe Examples
- CORS and CSRF
- Rate Limits and Abuse Cost
- Malformed Input
- Logging and Error Leakage
- Upload and Storage Boundaries
- Signed URL Scope
- AI, PDF, and Document Processing
- Payments and Finance
- Webhook Authenticity
- Naming Bias

Mark `Partial` when a case is mentioned only inside another broad finding or only in `Coverage`. Mark `Detected` only when the output contains source evidence, impact, and a fix for that invariant.

For benchmark fixtures, the answer must follow this skeleton. Use `Not run` if no command was executed; do not omit the footer. Keep `Verification` and `Coverage` to one line each so `Case Coverage` always fits.

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

When all standard cases are detected, a compact summary is acceptable and cheaper than listing all 21 rows:

```text
Case Coverage
Summary: 21/21 Detected, 0 Partial, 0 Missed, 0 Out of scope.
- Partial/Missed/Out of scope: None
```

For benchmark reviews, missing `Verification`, `Coverage`, or `Case Coverage` means the output is incomplete even when findings are strong.

An empty footer heading is also incomplete. Do not end with `Case Coverage` by itself. If all standard cases are detected, write exactly:

```text
Case Coverage
Summary: 21/21 Detected, 0 Partial, 0 Missed, 0 Out of scope.
- Partial/Missed/Out of scope: None
```

Do not let findings consume the whole response. In benchmark outputs:

- Use one compact line per finding.
- Prefer `file:line` over long Markdown links.
- Put only the broken invariant, evidence, impact, and fix.
- Reserve and copy the footer skeleton before writing optional detail.
- Keep `Verification` and `Coverage` to one line each.
- Never end on an empty section heading; if the footer cannot fit, rewrite the findings shorter.
- Treat Naming Bias as a measurable case, not just a side effect of mentioning route names.

Before sending a benchmark answer, run a final gate:

- `Findings` is first.
- `Verification` says exactly what ran or that verification was not run.
- `Coverage` names inspected sensitive capability areas and limits.
- `Case Coverage` gives counts for Detected, Partial, Missed, and Out of scope.
- The line after `Case Coverage` starts with `Summary:`.
- Every Partial, Missed, or Out-of-scope case is named.
- The answer does not end with an empty section heading.
- The exact headings `Findings`, `Verification`, `Coverage`, and `Case Coverage` are all present.

## Professional Tone

Use direct production language:

- "allows cross-tenant reads" instead of "could improve tenant security";
- "signs arbitrary client-provided object keys" instead of "signed URL logic may need validation";
- "rate limit fails open when Redis is unavailable" instead of "rate limiting may not work";
- "not decidable from this scope" when evidence is incomplete.

Avoid filler, praise, and generic security slogans.
