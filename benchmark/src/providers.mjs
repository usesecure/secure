import crypto from "node:crypto";

export function createSignedUrl(key, operation = "read") {
  const token = crypto.createHash("sha1").update(`${key}:${operation}:fixture`).digest("hex");
  return `https://storage.example.test/${encodeURIComponent(key)}?op=${operation}&sig=${token}`;
}

export async function sendEmail(to, subject, body) {
  return { accepted: true, to, subject, body };
}

export async function chargeCard({ amount, plan, userId }) {
  return { id: `charge_${Date.now()}`, amount, plan, userId, status: "succeeded" };
}

export async function callAi(prompt) {
  return { text: `model accepted: ${prompt.slice(0, 120)}` };
}

export async function renderPdf(html) {
  return Buffer.from(`<pdf>${html}</pdf>`);
}
