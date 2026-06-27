# Baseline Comparison

This benchmark is designed to measure whether a reviewer finds production and
security risks from code behavior, not from benchmark hints.

## Clean Target Setup

Create a neutral copy before testing a baseline model:

```powershell
Copy-Item -Recurse `
  "C:\Users\danie\Escritorio\Proyectos\presentacion\secure-fixture-21" `
  "C:\Users\danie\Escritorio\Proyectos\presentacion\review-target"

Remove-Item `
  "C:\Users\danie\Escritorio\Proyectos\presentacion\review-target\tests" `
  -Recurse -Force
```

Then remove benchmark hints from the copied target:

- README text that says the project is intentionally vulnerable.
- package metadata such as `secure-fixture-21`.
- strings such as `fixture`, `secure fixture`, `benchmark`, `21`, or `answer key`.
- tests or answer keys that enumerate expected cases.

The reviewed project should look like an ordinary service, for example:

```text
Admin Studio
A small administrative workspace service used for document operations, billing,
asset handling, and operational integrations.
```

## Baseline Prompt

Use this prompt to measure model-only behavior:

```text
ChatGPT, review this project before commit. Focus on production and security issues.

Do not use the secure skill.

Project:
C:\Users\danie\Escritorio\Proyectos\presentacion\review-target
```

## Secure Prompt

Use the same natural request, but allow skill selection:

```text
ChatGPT, review this project before commit. Focus on production and security issues.

Project:
C:\Users\danie\Escritorio\Proyectos\presentacion\review-target
```

## Observed Baseline Result

In a clean run without `secure`, the model found several critical issues but did
not cover the full invariant set.

```text
Summary: 12/21 Detected, 5 Partial, 4 Missed, 0 Out of scope.
```

The baseline detected obvious high-risk areas:

- forged/default authentication;
- unauthenticated admin bootstrap;
- destructive unauthenticated helper route;
- broad tenant isolation failure;
- public private-feed leak;
- secret/config exposure;
- forged payment webhook;
- role escalation;
- arbitrary signed URL generation;
- debug/error leakage;
- unsafe `.env.example`;
- partial naming-bias issues around harmless route names.

The baseline was incomplete because it grouped or missed several invariants:

- owner scope was grouped into tenant isolation instead of reported separately;
- mass assignment was missed;
- publish/state-transition rules were only mentioned indirectly;
- upload/storage boundaries were missed;
- CORS/CSRF was missed;
- fail-open policy behavior was not finalized as a finding;
- public preview side effects were missed;
- AI/PDF external-cost and document-processing abuse was missed;
- checkout amount tampering was missed;
- public contact/lead rate limiting was missed;
- malformed input and DoS handling were missed;
- public side effects were not separated from data exposure.

## What Secure Should Prove

`secure` should not merely find some critical bugs. A passing run should show a
capability-level review:

- inspect routes, auth/session helpers, config, uploads, signed URLs, payments,
  webhooks, AI/PDF flows, public writes, and naming-biased routes;
- report atomic findings by broken invariant instead of bundling unrelated bugs;
- include evidence with file and line;
- explain production impact and concrete fix;
- finish with `Verification`, `Coverage`, and `Case Coverage`.

Expected benchmark footer:

```text
Case Coverage
Summary: 21/21 Detected, 0 Partial, 0 Missed, 0 Out of scope.
- Partial/Missed/Out of scope: None
```

## Evaluation Notes

This benchmark is a review-quality test, not a SAST keyword test. Award credit
only when the reviewer proves the broken invariant from source code. A route name
such as `safe`, `helper`, `preview`, `asset`, or `template` is not evidence of
safety; the reviewer must follow the behavior to the sensitive sink.
