import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

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
