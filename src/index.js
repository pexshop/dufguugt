import { handleAuth, authorizeRoom } from "./auth.js";
import { AuthStore } from "./auth-store.js";

const MAX_HISTORY = 100;
const MAX_MESSAGE_BYTES = 16_000;

export { AuthStore };

export class ChatRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sessions = new Map();
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("WebSocket connection required", { status: 426 });
    }

    const sessionHash = request.headers.get("X-BP-Session-Hash");
    if (!sessionHash) return new Response("Authentication required", { status: 401 });

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.sessions.set(server, sessionHash);
    this.ctx.storage.setAlarm(Date.now() + 5_000).catch(() => {});

    server.addEventListener("message", async (event) => {
      try {
        if (!(await this.isSessionActive(sessionHash))) {
          try { server.close(1008, "Session revoked"); } catch {}
          this.sessions.delete(server);
          return;
        }
        if (typeof event.data !== "string" || event.data.length > MAX_MESSAGE_BYTES) {
          server.send(JSON.stringify({ type: "error", message: "Message too large or invalid." }));
          return;
        }
        const packet = JSON.parse(event.data);
        if (packet.type === "auth_ping") {
          server.send(JSON.stringify({ type: "auth_pong" }));
          return;
        }
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
        for (const [socket, socketSessionHash] of this.sessions) {
          if (!(await this.isSessionActive(socketSessionHash))) {
            try { socket.close(1008, "Session revoked"); } catch {}
            this.sessions.delete(socket);
            continue;
          }
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

  async alarm() {
    for (const [socket, sessionHash] of this.sessions) {
      if (!(await this.isSessionActive(sessionHash))) {
        try { socket.close(1008, "Session revoked"); } catch {}
        this.sessions.delete(socket);
      }
    }
    if (this.sessions.size > 0) {
      await this.ctx.storage.setAlarm(Date.now() + 5_000);
    }
  }

  async isSessionActive(sessionHash) {
    try {
      const stub = this.env.AUTH_STORE.get(this.env.AUTH_STORE.idFromName("global"));
      const response = await stub.fetch("https://auth-store.internal/_internal/store", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ op: "check-session", key: sessionHash }),
      });
      if (!response.ok) return false;
      const result = await response.json();
      return result.active === true;
    } catch {
      return false;
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return await handleAuth(request, env);
    }

    if (url.pathname === "/health") {
      return Response.json({ name: "BLACK-PRIVATE", status: "ok", auth: "device-gated" });
    }

    const match = url.pathname.match(/^\/room\/([a-f0-9]{32})$/);
    if (match && request.headers.get("Upgrade") === "websocket") {
      let session = null;
      try { session = await authorizeRoom(request, env); } catch {}
      if (!session) return new Response("Authentication required", { status: 401 });
      const headers = new Headers(request.headers);
      headers.set("X-BP-Session-Hash", session.hash);
      const authorizedRequest = new Request(request, { headers });
      const id = env.CHAT_ROOMS.idFromName(match[1]);
      return env.CHAT_ROOMS.get(id).fetch(authorizedRequest);
    }

    return env.ASSETS.fetch(request);
  }
};
