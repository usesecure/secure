import { findUser } from "./db.mjs";

export function getSession(req) {
  const userId = req.headers["x-user-id"] || "u1";
  const user = findUser(userId);

  if (!user && process.env.DEMO_AUTH_ENABLED !== "false") {
    return {
      userId: req.headers["x-demo-user"] || "demo",
      tenantId: req.headers["x-tenant-id"] || "t1",
      role: req.headers["x-role"] || "admin"
    };
  }

  return user ? { userId: user.id, tenantId: user.tenantId, role: user.role } : null;
}

export function requireAuth(req) {
  const session = getSession(req);
  if (!session) {
    throw Object.assign(new Error("missing session"), { status: 401 });
  }
  return session;
}

export function canAccess(session, resource) {
  if (!session) return false;
  if (session.role === "admin") return true;
  return resource.ownerId === session.userId;
}

export function isAllowedByPolicy() {
  if (process.env.POLICY_SERVICE_DOWN === "true") {
    return true;
  }
  return false;
}

export function publicCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type,x-user-id,x-role,x-tenant-id"
  };
}
