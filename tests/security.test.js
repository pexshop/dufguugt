import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AuthStore } from "../src/auth-store.js";

const auth = await readFile(new URL("../src/auth.js", import.meta.url), "utf8");
const store = await readFile(new URL("../src/auth-store.js", import.meta.url), "utf8");
const worker = await readFile(new URL("../src/index.js", import.meta.url), "utf8");

test("one-time challenges are consumed atomically", () => {
  assert.match(store, /op === "take"[\s\S]*?storage\.transaction/);
  assert.match(auth, /const take = async/);
  assert.match(auth, /Login challenge already used/);
  assert.match(auth, /Enrollment flow or invite already used/);
});

test("enrollment invitations are claimed atomically and expire", () => {
  assert.match(store, /op === "claim-invite"[\s\S]*?storage\.transaction/);
  assert.match(store, /invite\.used \|\| invite\.expiresAt < Date\.now\(\)/);
  assert.match(auth, /claimInvite\(env/);
});

test("administrator bootstrap is single-use under concurrent requests", () => {
  assert.match(store, /op === "claim-bootstrap"[\s\S]*?storage\.transaction/);
  assert.match(auth, /claimBootstrap\(env\)/);
});

test("every active chat socket is revalidated before broadcasts and by alarm", () => {
  assert.match(worker, /async alarm\(\)/);
  assert.match(worker, /setAlarm\(Date\.now\(\) \+ 5_000\)/);
  assert.match(worker, /for \(const \[socket, socketSessionHash\] of this\.sessions\)/);
  assert.match(worker, /isSessionActive\(socketSessionHash\)/);
  assert.match(worker, /socket\.close\(1008, "Session revoked"\)/);
});

class MemoryStorage {
  constructor() { this.values = new Map(); this.tail = Promise.resolve(); }
  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, value); }
  async delete(key) { return this.values.delete(key); }
  async list({ prefix = "", limit = 1000 } = {}) {
    return new Map([...this.values.entries()].filter(([key]) => key.startsWith(prefix)).slice(0, limit));
  }
  async transaction(callback) {
    let release;
    const previous = this.tail;
    this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    try {
      return await callback({
        get: async key => this.values.get(key),
        put: async (key, value) => this.values.set(key, value),
        delete: async key => this.values.delete(key),
      });
    } finally { release(); }
  }
}

async function invoke(storeInstance, body) {
  const response = await storeInstance.fetch(new Request("https://auth-store.internal/_internal/store", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  }));
  assert.equal(response.status, 200);
  return response.json();
}

test("take operation allows exactly one concurrent consumer", async () => {
  const storage = new MemoryStorage();
  const instance = new AuthStore({ storage }, {});
  await storage.put("flow:login:one", { challenge: "one-use" });
  const results = await Promise.all([
    invoke(instance, { op: "take", key: "flow:login:one" }),
    invoke(instance, { op: "take", key: "flow:login:one" }),
  ]);
  assert.equal(results.filter(result => result.value?.challenge === "one-use").length, 1);
  assert.equal(results.filter(result => result.value === null).length, 1);
});

test("invite claim is single-use under concurrent enrollment finishes", async () => {
  const storage = new MemoryStorage();
  const instance = new AuthStore({ storage }, {});
  await storage.put("invite:abc", { used: false, expiresAt: Date.now() + 60_000 });
  const results = await Promise.all([
    invoke(instance, { op: "claim-invite", key: "invite:abc" }),
    invoke(instance, { op: "claim-invite", key: "invite:abc" }),
  ]);
  assert.equal(results.filter(result => result.claimed === true).length, 1);
  assert.equal(results.filter(result => result.claimed === false).length, 1);
});

test("administrator bootstrap can be claimed only once", async () => {
  const storage = new MemoryStorage();
  const instance = new AuthStore({ storage }, {});
  const results = await Promise.all([
    invoke(instance, { op: "claim-bootstrap" }),
    invoke(instance, { op: "claim-bootstrap" }),
  ]);
  assert.equal(results.filter(result => result.claimed === true).length, 1);
  assert.equal(results.filter(result => result.claimed === false).length, 1);
});
