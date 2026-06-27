# Secure

Production security review and hardening for Codex.

[![skills.sh](https://skills.sh/b/danielcadev/secure)](https://skills.sh/danielcadev/secure)

Secure is a Codex skill that reviews whole projects by capability, data flow, and broken invariants instead of filename assumptions. It scans large repositories compactly, confirms real risks from source, fixes confirmed issues when asked, verifies the result, and reports coverage without claiming a project is magically "100% secure".

## Why this exists

Most AI security reviews miss the dangerous parts of real codebases:

- trusted request headers that create admin sessions;
- authentication mistaken for authorization;
- tenant and owner checks only applied to list pages;
- mass assignment into policy fields;
- public routes with harmless names like `preview`, `helper`, `asset`, or `safe`;
- fail-open Redis, cache, webhook, payment, AI, PDF, and storage flows;
- findings lists that never say what was actually verified.

Secure is built to catch those misses.

## What is included

```text
skills/secure/ The Codex skill: SKILL.md, references, scanners, UI metadata
site/          Astro marketing site and case library
benchmark/    21-case intentionally vulnerable fixture used to test the review behavior
```

The skill uses the standard Skills CLI discovery layout:

```text
skills/secure/SKILL.md
```

That layout is intentional. It helps `npx skills add danielcadev/secure`
discover the package cleanly and gives Skills.sh the clearest index path.

## Core workflows

Secure routes natural language to concrete workflows:

- `review`: read-only production/security review.
- `audit`: broader production readiness pass.
- `scrape`: compact low-token project inventory.
- `secure`: scan, confirm, fix, verify, rescan, and report fix coverage.
- `threat-model`: map actors, assets, trust boundaries, sinks, and controls.
- `compare`: evaluate review quality, missed findings, severity drift, and naming bias.

Users do not need to know these commands. Requests like "review this project before commit" and "make it production ready" are enough.

## Commands

All commands are accessed through the single `secure` skill. Use natural language,
or call a command directly when you want a specific workflow.

| Command | What it does |
| --- | --- |
| `review [path or diff]` | Read-only production/security review. Findings first, with evidence, impact, fixes, verification limits, and residual risk. |
| `audit [path]` | Broader production-readiness pass across routes, auth, config, secrets, CORS/CSRF, logs, rate limits, storage, webhooks, payments, and fail-open behavior. |
| `scrape [path]` | Token-efficient local project scan. Produces a compact review pack with risky files, routes, possible secrets, capability clusters, and inspection plan. |
| `inventory [path]` | Sensitive capability inventory only: entry points, trusted inputs, sinks, expected guards, and recommended review order. |
| `harden [target]` | Implement fixes for confirmed findings, preserve the broken invariant in code, and verify with focused checks. |
| `harden-all [path]` | Full scan, confirm, fix, verify, rescan, and iterate until confirmed Critical/High issues are fixed or blocked. |
| `secure [path]` | Alias for `harden-all`. Use when the goal is "make this production ready" or "fix the security issues". |
| `threat-model [feature]` | Map actors, assets, trust boundaries, user-controlled inputs, sensitive sinks, abuse cases, and required controls before coding. |
| `compare [reviews]` | Compare review outputs for missed findings, severity drift, naming bias, weak evidence, skipped surfaces, and fix quality. |

Usage examples:

```text
Use secure. Review this project before commit:
C:\path\to\project

Use secure. Audit this app before production:
C:\path\to\project

Use secure. Scrape this monorepo and give me the risky surfaces:
C:\path\to\repo

Use secure. Harden all confirmed Critical and High findings:
C:\path\to\project

Use secure. Threat-model the upload and signed URL flow.

Use secure. Compare these two security reviews and tell me what was missed.
```

## Benchmark result

The included fixture covers 21 review invariants:

1. Authentication Trust
2. Authorization Dominance
3. Tenant Boundary
4. Owner Scope
5. Mass Assignment
6. State Transition Invariants
7. Route Exposure
8. Side Effect Reachability
9. Fail-open Behavior
10. Visibility Rules
11. Secrets and Unsafe Examples
12. CORS and CSRF
13. Rate Limits and Abuse Cost
14. Malformed Input
15. Logging and Error Leakage
16. Upload and Storage Boundaries
17. Signed URL Scope
18. AI, PDF, and Document Processing
19. Payments and Finance
20. Webhook Authenticity
21. Naming Bias

Expected benchmark footer:

```text
Case Coverage
Summary: 21/21 Detected, 0 Partial, 0 Missed, 0 Out of scope.
- Partial/Missed/Out of scope: None
```

## Install locally

Install from the Skills CLI:

```bash
npx skills add danielcadev/secure
```

Copy the skill folder into your Codex skills directory:

```powershell
Copy-Item -Recurse .\skills\secure "$env:USERPROFILE\.codex\skills\secure"
```

Then start a new Codex chat and use:

```text
Use secure. Review this project before commit, focused on production and security issues:
C:\path\to\project
```

For hardening:

```text
Use secure. Make this project production ready. Fix confirmed Critical and High findings, verify, rescan, and report fix coverage:
C:\path\to\project
```

## Run checks

Benchmark fixture:

```bash
cd benchmark
npm test
```

Site:

```bash
cd site
npm install
npm run build
```

Vercel:

```bash
vercel
```

This repository includes `vercel.json`, so Vercel can deploy from the repository
root while building the Astro site in `site/` and publishing `site/dist`. On
GitHub Pages the site is built under `/secure`; on Vercel it is built at `/`.
Set `PUBLIC_SITE_URL` in Vercel if you want canonical URLs to use a custom
domain.

Skill validation, from this repository root:

```bash
python /path/to/quick_validate.py skills/secure
python -m py_compile skills/secure/scripts/project_scraper.py skills/secure/scripts/inventory_scan.py
```

## What Secure optimizes for

- evidence over generic best practices;
- source-confirmed findings over keyword matches;
- capability review over filename assumptions;
- scoped fix coverage over false confidence;
- token-efficient inspection for large projects;
- multi-language invariants instead of framework-specific tunnel vision.

## License

MIT.
