export const users = [
  { id: "u1", tenantId: "t1", role: "member", email: "owner@alpha.test" },
  { id: "u2", tenantId: "t2", role: "member", email: "guest@beta.test" },
  { id: "admin1", tenantId: "t1", role: "admin", email: "admin@alpha.test" }
];

export const documents = [
  {
    id: "doc-alpha-private",
    tenantId: "t1",
    ownerId: "u1",
    title: "Alpha private plan",
    visibility: "private",
    status: "draft",
    storageKey: "t1/private/alpha-plan.pdf",
    body: "<p>private alpha plan</p>"
  },
  {
    id: "doc-beta-private",
    tenantId: "t2",
    ownerId: "u2",
    title: "Beta private plan",
    visibility: "private",
    status: "draft",
    storageKey: "t2/private/beta-plan.pdf",
    body: "<script>alert('preview')</script>"
  }
];

export const payments = [
  { id: "pay-alpha", tenantId: "t1", userId: "u1", amount: 9900, status: "paid", plan: "pro" }
];

export const auditLog = [];
export const jobs = [];

export function findUser(id) {
  return users.find((user) => user.id === id);
}

export function findDocument(id) {
  return documents.find((document) => document.id === id);
}

export function findPayment(id) {
  return payments.find((payment) => payment.id === id);
}
