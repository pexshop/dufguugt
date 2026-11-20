export class AuthStore {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/_internal/store") {
      return new Response("Not found", { status: 404 });
    }

    let body;
    try { body = await request.json(); } catch { return new Response("Bad request", { status: 400 }); }
    const { op, key, value, prefix } = body || {};

    if (op === "get" && typeof key === "string") {
      return Response.json({ value: (await this.ctx.storage.get(key)) ?? null });
    }
    if (op === "check-session" && typeof key === "string") {
      const session = await this.ctx.storage.get(`session:${key}`);
      if (!session || session.expiresAt < Date.now()) return Response.json({ active: false });
      const member = await this.ctx.storage.get(`member:${session.memberId}`);
      const device = await this.ctx.storage.get(`device:${session.deviceId}`);
      const active = Boolean(member && member.status === "approved" &&
        device && device.status === "approved" && device.memberId === member.id);
      return Response.json({ active });
    }
    if (op === "take" && typeof key === "string") {
      const result = await this.ctx.storage.transaction(async (txn) => {
        const current = await txn.get(key);
        if (current === undefined) return null;
        await txn.delete(key);
        return current;
      });
      return Response.json({ value: result ?? null });
    }
    if (op === "claim-invite" && typeof key === "string") {
      const result = await this.ctx.storage.transaction(async (txn) => {
        const invite = await txn.get(key);
        if (!invite || invite.used || invite.expiresAt < Date.now()) return false;
        invite.used = true;
        invite.usedAt = Date.now();
        await txn.put(key, invite);
        return true;
      });
      return Response.json({ claimed: result });
    }
    if (op === "claim-bootstrap") {
      const result = await this.ctx.storage.transaction(async (txn) => {
        const marker = "system:admin-bootstrap-used";
        if (await txn.get(marker)) return false;
        await txn.put(marker, true);
        return true;
      });
      return Response.json({ claimed: result });
    }
    if (op === "put" && typeof key === "string") {
      await this.ctx.storage.put(key, value);
      return Response.json({ ok: true });
    }
    if (op === "delete" && typeof key === "string") {
      await this.ctx.storage.delete(key);
      return Response.json({ ok: true });
    }
    if (op === "list" && typeof prefix === "string") {
      const entries = await this.ctx.storage.list({ prefix, limit: 1000 });
      return Response.json({ entries: [...entries.entries()] });
    }
    return new Response("Invalid operation", { status: 400 });
  }
}
