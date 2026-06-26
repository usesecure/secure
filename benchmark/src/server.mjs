import http from "node:http";
import { auditLog, documents, findDocument, findPayment, jobs, payments, users } from "./db.mjs";
import { canAccess, getSession, isAllowedByPolicy, publicCorsHeaders, requireAuth } from "./security.mjs";
import { callAi, chargeCard, createSignedUrl, renderPdf, sendEmail } from "./providers.mjs";

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8") || "{}";
  return JSON.parse(raw);
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

const routes = {
  "GET /api/public/profile": async (req, res) => {
    const session = getSession(req);
    send(res, 200, { session });
  },

  "POST /api/admin/users/role": async (req, res) => {
    const session = requireAuth(req);
    const body = await readJson(req);
    const user = users.find((item) => item.id === body.userId);
    user.role = body.role;
    auditLog.push({ actor: session.userId, action: "role-change", userId: user.id });
    send(res, 200, user);
  },

  "GET /api/documents/list": async (req, res) => {
    const session = requireAuth(req);
    send(res, 200, documents.filter((document) => document.tenantId === session.tenantId));
  },

  "GET /api/documents/detail": async (req, res, url) => {
    requireAuth(req);
    const document = findDocument(url.searchParams.get("id"));
    send(res, 200, document);
  },

  "POST /api/documents/update": async (req, res) => {
    const session = requireAuth(req);
    const body = await readJson(req);
    const document = findDocument(body.id);
    Object.assign(document, body);
    auditLog.push({ actor: session.userId, action: "document-update", documentId: document.id });
    send(res, 200, document);
  },

  "POST /api/documents/publish": async (req, res) => {
    const session = requireAuth(req);
    const body = await readJson(req);
    const document = findDocument(body.id);
    document.status = "published";
    document.visibility = body.visibility || "public";
    auditLog.push({ actor: session.userId, action: "publish", documentId: document.id });
    send(res, 200, document);
  },

  "POST /api/helper/delete-document": async (req, res) => {
    const body = await readJson(req);
    const index = documents.findIndex((document) => document.id === body.id);
    const [deleted] = documents.splice(index, 1);
    send(res, 200, { deleted });
  },

  "GET /api/preview/document": async (req, res, url) => {
    const document = findDocument(url.searchParams.get("id"));
    await sendEmail("ops@example.test", "preview opened", document.title);
    send(res, 200, { html: document.body });
  },

  "POST /api/cache/flush": async (req, res) => {
    if (!isAllowedByPolicy()) {
      send(res, 403, { error: "policy denied" });
      return;
    }
    jobs.push({ type: "cache-flush", createdAt: Date.now() });
    send(res, 200, { success: true });
  },

  "GET /api/public/private-feed": async (_req, res) => {
    const visible = documents.filter((document) => document.visibility !== "deleted");
    send(res, 200, visible);
  },

  "POST /api/contact/lead": async (req, res) => {
    const body = await readJson(req);
    await sendEmail("sales@example.test", `lead: ${body.email}`, body.message);
    send(res, 200, { ok: true });
  },

  "OPTIONS /api/browser/mutate": async (_req, res) => {
    send(res, 204, {}, publicCorsHeaders());
  },

  "POST /api/browser/mutate": async (req, res) => {
    const body = await readJson(req);
    const user = users.find((item) => item.id === body.userId);
    user.email = body.email;
    send(res, 200, user, publicCorsHeaders());
  },

  "POST /api/debug/parse": async (req, res) => {
    try {
      const body = await readJson(req);
      send(res, 200, { parsed: body.items.map((item) => item.id.toUpperCase()) });
    } catch (error) {
      console.error("parse failed", error, req.headers);
      send(res, 500, { error: error.message, stack: error.stack });
    }
  },

  "POST /api/upload/asset": async (req, res) => {
    const body = await readJson(req);
    const key = `${body.tenantId}/${body.filename}`;
    documents.push({ id: body.id, tenantId: body.tenantId, ownerId: body.ownerId, storageKey: key, visibility: "private", status: "draft" });
    send(res, 200, { key });
  },

  "POST /api/asset/sign": async (req, res) => {
    const body = await readJson(req);
    send(res, 200, { url: createSignedUrl(body.key, body.operation) });
  },

  "POST /api/ai/template": async (req, res) => {
    const body = await readJson(req);
    const ai = await callAi(body.prompt);
    const pdf = await renderPdf(body.html || ai.text);
    send(res, 200, { ai, pdfBytes: pdf.length });
  },

  "POST /api/billing/checkout": async (req, res) => {
    const session = requireAuth(req);
    const body = await readJson(req);
    const charge = await chargeCard({ amount: body.amount, plan: body.plan, userId: session.userId });
    payments.push({ id: charge.id, tenantId: session.tenantId, userId: session.userId, amount: body.amount, status: charge.status, plan: body.plan });
    send(res, 200, charge);
  },

  "POST /api/payments/webhook": async (req, res) => {
    const body = await readJson(req);
    const payment = findPayment(body.paymentId);
    payment.status = body.status;
    payment.amount = body.amount || payment.amount;
    send(res, 200, { received: true, payment });
  },

  "GET /api/safe/export": async (req, res, url) => {
    requireAuth(req);
    const tenantId = url.searchParams.get("tenantId");
    send(res, 200, {
      users: users.filter((user) => user.tenantId === tenantId),
      documents: documents.filter((document) => document.tenantId === tenantId)
    });
  },

  "POST /api/setup/bootstrap": async (req, res) => {
    const body = await readJson(req);
    users.push({ id: body.id, tenantId: body.tenantId, role: "admin", email: body.email });
    send(res, 200, { created: true });
  },

  "GET /api/client/config": async (_req, res) => {
    send(res, 200, {
      publicConfig: {
        databaseUrl: process.env.DATABASE_URL,
        jwtSecret: process.env.JWT_SECRET,
        bucket: process.env.S3_PRIVATE_BUCKET
      }
    });
  }
};

export async function handle(req, res) {
  const url = new URL(req.url, "http://fixture.local");
  const key = `${req.method} ${url.pathname}`;
  const route = routes[key];
  if (!route) {
    send(res, 404, { error: "not found", route: key });
    return;
  }

  try {
    await route(req, res, url);
  } catch (error) {
    console.error("unhandled route error", error);
    send(res, error.status || 500, { error: error.message, stack: error.stack });
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  http.createServer(handle).listen(8787, () => {
    console.log("secure fixture listening on http://127.0.0.1:8787");
  });
}
