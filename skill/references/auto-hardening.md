# Auto Hardening

Use this reference when the user asks to fix, harden, secure, make production-ready, or reduce most security findings across a whole project.

The goal is to maximize confirmed fixes, not to claim perfect security. Report fix coverage from actual findings and verification.

## Success Target

Aim for:

- 100% of confirmed `Critical` and `High` findings fixed, or explicitly blocked with reason;
- most confirmed `Medium` findings fixed when the change is low-risk and local;
- tests/typecheck/lint green where available, or exact blockers reported;
- no known regression in auth, routing, schema, storage, or public write flows.

Do not promise "100% secure". Say "fixed 100% of confirmed Critical/High findings in the reviewed scope" only when that is true.

## Harden-All Workflow

1. Establish safety baseline.
   - Inspect `git status`.
   - Identify package manager, test/typecheck/lint scripts, framework, route structure, env/config files.
   - Preserve unrelated user changes. Do not revert files you did not need to touch.

2. Generate a compact project pack.
   - Run:

     ```bash
     python <skill-dir>/scripts/project_scraper.py <project-path> --budget-chars 24000 --top-files 50
     ```

   - Use the pack to choose files. Do not treat pack leads as findings.

3. Confirm findings from source.
   - Read the route/helper/sink code for each high-risk lead.
   - Classify confirmed issues by invariant: auth, authorization, tenant scope, mass assignment, signed URL/storage, public abuse, secrets, CORS/CSRF, validation, errors/logs, fail-open config.

4. Fix in safe batches.
   - Batch 1: secrets and config exposure.
   - Batch 2: auth/session trust boundaries.
   - Batch 3: authorization, tenant/owner scope, direct object references.
   - Batch 4: mass assignment, schema validation, state transitions.
   - Batch 5: storage/upload/signed URL ownership.
   - Batch 6: public endpoint abuse controls, rate limits, CORS/CSRF.
   - Batch 7: error/log sanitization, timeouts, fail-open behavior.

5. Verify after each meaningful batch.
   - Run the narrowest relevant tests first.
   - Run typecheck/lint/build if available and not prohibitively expensive.
   - Add or update focused tests for security invariants when the project has a test pattern.

6. Re-scan and iterate.
   - Re-run the scraper.
   - Re-run focused `rg` searches for the fixed pattern classes.
   - Revisit any remaining confirmed Critical/High issues.
   - Continue until no confirmed Critical/High issues remain, verification blocks progress, or further fixes require product decisions.

## Fix Patterns

### Auth/session

- Replace client-controlled identity headers with trusted server-side auth.
- Validate JWT/session signatures server-side.
- Keep role, tenant, organization, and user IDs from trusted identity data, not request body/query/header values.

### Authorization and object scope

- Scope lookup/update/delete queries at the sink: `id` plus tenant/owner/workspace constraints.
- Call canonical permission helpers before mutation.
- Return `404` for inaccessible private objects when existence should not leak.
- Distinguish global admin from tenant admin.

### Mass assignment

- Split input DTOs by action and role.
- Reject policy fields from normal user payloads.
- Use schema validation with explicit allowlists.
- Derive sensitive fields server-side: role, tenant, owner, status transitions, approval timestamps, prices, quotas.

### Storage and signed URLs

- Never sign, delete, or proxy arbitrary client-provided object keys.
- Resolve object keys through DB records scoped to the current tenant/user.
- Normalize and constrain prefixes.
- Separate public and private buckets or policies when possible.

### Public write and expensive endpoints

- Add rate limits, quotas, CAPTCHA or abuse controls where appropriate.
- Fail closed or degrade safely when Redis/rate-limit backends are unavailable.
- Add body size limits and schema validation.
- Add timeouts around AI, PDF, browser, OCR, email, webhook, and external API calls.

### Errors and logs

- Return generic client errors.
- Log sanitized details server-side.
- Do not log tokens, cookies, raw documents, prompts, provider payloads, payment details, storage keys, or database URLs.

### Secrets

- Remove live secrets from tracked files.
- Replace with placeholders in examples.
- Add local env files to ignore rules where appropriate.
- State clearly that exposed secrets must be rotated outside the repo. Code changes cannot rotate already-leaked credentials.

## Completion Report

End with:

- changed files;
- confirmed findings fixed;
- remaining confirmed findings;
- blocked items requiring credentials/product decisions/external secret rotation;
- verification commands and results;
- fix coverage:

```text
Fix coverage: 8/8 confirmed Critical/High fixed, 5/7 Medium fixed, 2 Medium deferred with rationale.
```

Never calculate coverage from scraper leads. Calculate it from confirmed findings only.
