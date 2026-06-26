# Secure Fixture 21

This is an intentionally vulnerable mini project for testing the `secure` skill.

It contains 21 seeded production-security cases across authentication, authorization,
tenant scope, object ownership, mass assignment, state transitions, route exposure,
side effects, fail-open behavior, visibility, secrets, CORS/CSRF, rate limits,
malformed input, logging, uploads, signed URLs, AI/PDF processing, payments,
webhooks, and naming bias.

Do not deploy this project. The vulnerabilities are deliberate.

## Run

```bash
npm test
node src/server.mjs
```

## Benchmark Contract

The answer key lives outside this project at `../secure-fixture-21-answer-key.json`.
Keep it outside the reviewed scope so the scanner cannot read the expected findings.
