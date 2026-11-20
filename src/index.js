const MAX_HISTORY = 100;
const MAX_MESSAGE_BYTES = 16_000;

export class ChatRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sessions = new Set();
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("WebSocket connection required", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.sessions.add(server);

    server.addEventListener("message", async (event) => {
      try {
        if (typeof event.data !== "string" || event.data.length > MAX_MESSAGE_BYTES) {
          server.send(JSON.stringify({ type: "error", message: "Message too large or invalid." }));
          return;
        }
        const packet = JSON.parse(event.data);
        if (packet.type !== "message" || typeof packet.id !== "string" ||
            typeof packet.iv !== "string" || typeof packet.ciphertext !== "string" ||
            typeof packet.createdAt !== "number") return;

        const record = {
          type: "message",
          id: packet.id.slice(0, 80),
          iv: packet.iv,
          ciphertext: packet.ciphertext,
          createdAt: packet.createdAt
        };
        await this.ctx.storage.put("msg:" + record.createdAt + ":" + record.id, record);
        const keys = await this.ctx.storage.list({ prefix: "msg:" });
        if (keys.size > MAX_HISTORY) {
          const excess = keys.size - MAX_HISTORY;
          let removed = 0;
          for (const key of keys.keys()) {
            if (removed++ >= excess) break;
            await this.ctx.storage.delete(key);
          }
        }
        const outgoing = JSON.stringify(record);
        for (const socket of this.sessions) {
          try { socket.send(outgoing); } catch { this.sessions.delete(socket); }
        }
      } catch {
        try { server.send(JSON.stringify({ type: "error", message: "Invalid message." })); } catch {}
      }
    });

    const close = () => this.sessions.delete(server);
    server.addEventListener("close", close);
    server.addEventListener("error", close);

    this.ctx.storage.list({ prefix: "msg:" }).then((history) => {
      const records = [...history.values()].sort((a, b) => a.createdAt - b.createdAt);
      for (const record of records) {
        try { server.send(JSON.stringify(record)); } catch { break; }
      }
    }).catch(() => {});

    return new Response(null, { status: 101, webSocket: client });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ name: "BLACK-PRIVATE", status: "ok" });
    }

    const match = url.pathname.match(/^\/room\/([a-f0-9]{32})$/);
    if (match && request.headers.get("Upgrade") === "websocket") {
      const id = env.CHAT_ROOMS.idFromName(match[1]);
      return env.CHAT_ROOMS.get(id).fetch(request);
    }

    return env.ASSETS.fetch(request);
  }
};
