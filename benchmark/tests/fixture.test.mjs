import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const server = fs.readFileSync(path.join(root, "src", "server.mjs"), "utf8");
const security = fs.readFileSync(path.join(root, "src", "security.mjs"), "utf8");
const envExample = fs.readFileSync(path.join(root, ".env.example"), "utf8");

const expectedCases = [
  ["Authentication Trust", "GET /api/public/profile"],
  ["Authorization Dominance", "POST /api/admin/users/role"],
  ["Tenant Boundary", "GET /api/documents/detail"],
  ["Owner Scope", "POST /api/documents/update"],
  ["Mass Assignment", "POST /api/documents/update"],
  ["State Transition Invariants", "POST /api/documents/publish"],
  ["Route Exposure", "POST /api/setup/bootstrap"],
  ["Side Effect Reachability", "GET /api/preview/document"],
  ["Fail-open Behavior", "POST /api/cache/flush"],
  ["Visibility Rules", "GET /api/public/private-feed"],
  ["Secrets and Unsafe Examples", ".env.example"],
  ["CORS and CSRF", "POST /api/browser/mutate"],
  ["Rate Limits and Abuse Cost", "POST /api/contact/lead"],
  ["Malformed Input", "POST /api/debug/parse"],
  ["Logging and Error Leakage", "POST /api/debug/parse"],
  ["Upload and Storage Boundaries", "POST /api/upload/asset"],
  ["Signed URL Scope", "POST /api/asset/sign"],
  ["AI, PDF, and Document Processing", "POST /api/ai/template"],
  ["Payments and Finance", "POST /api/billing/checkout"],
  ["Webhook Authenticity", "POST /api/payments/webhook"],
  ["Naming Bias", "GET /api/safe/export"]
];

test("fixture contains exactly 21 expected security cases", () => {
  assert.equal(expectedCases.length, 21);
  assert.equal(new Set(expectedCases.map(([name]) => name)).size, 21);
  assert.equal(new Set(expectedCases.map(([, route]) => route)).size, 19);
});

test("all expected routes or files are present in the vulnerable fixture", () => {
  for (const [caseName, routeOrFile] of expectedCases) {
    if (routeOrFile === ".env.example") {
      assert.match(envExample, /DATABASE_URL|JWT_SECRET|DEMO_AUTH_ENABLED/);
      continue;
    }

    const [method, route] = routeOrFile.split(" ");
    assert.ok(server.includes(`"${method} ${route}"`), `missing route for ${caseName}: ${routeOrFile}`);
  }
});

test("benchmark includes naming-bias route names that should not be trusted", () => {
  for (const name of ["public", "preview", "helper", "asset", "template", "safe"]) {
    assert.match(server, new RegExp(`/api/[^"]*${name}[^"]*`), `missing biased route name ${name}`);
  }
});

test("seeded vulnerabilities include concrete dangerous sinks", () => {
  const combined = `${server}\n${security}\n${envExample}`;
  for (const sink of [
    "Object.assign(document, body)",
    "createSignedUrl(body.key",
    "chargeCard({ amount: body.amount",
    "payment.status = body.status",
    "Access-Control-Allow-Origin",
    "error.stack",
    "sendEmail(",
    "callAi(",
    "renderPdf("
  ]) {
    assert.ok(combined.includes(sink), `missing sink ${sink}`);
  }
});
