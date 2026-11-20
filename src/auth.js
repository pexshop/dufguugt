import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const unb64u = (value) => Uint8Array.from(
  atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)),
  (c) => c.charCodeAt(0),
);
const randomId = (n = 24) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const digest = async (value) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(value)));
const json = (data, status = 200, headers = {}) =>
  Response.json(data, { status, headers });
const fail = (message, status = 400) => json({ error: message }, status);

async function store(env, op, key, value) {
  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const response = await stub.fetch("https://auth-store.internal/_internal/store", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ op, key, value }),
  });
  if (!response.ok) throw new Error("Authentication storage unavailable");
  return response.json();
}
const get = async (env, key) => (await store(env, "get", key)).value;
const put = (env, key, value) => store(env, "put", key, value);
const del = (env, key) => store(env, "delete", key);

function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}
function sessionCookie(token) {
  return `bp_session=${token}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookie() {
  return "bp_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
}
function config(env) {
  if (!env.RP_ID || !env.EXPECTED_ORIGIN || !env.ADMIN_BOOTSTRAP_SECRET) {
    throw new Error("Server authentication configuration is incomplete");
  }
  return { rpID: env.RP_ID, origin: env.EXPECTED_ORIGIN };
}
function sameOrigin(request, env) {
  return request.headers.get("Origin") === env.EXPECTED_ORIGIN;
}
async function currentSession(request, env) {
  const token = cookieValue(request, "bp_session");
  if (!token) return null;
  const hash = await digest(token);
  const session = await get(env, `session:${hash}`);
  if (!session || session.expiresAt < Date.now()) return null;
  const member = await get(env, `member:${session.memberId}`);
  const device = await get(env, `device:${session.deviceId}`);
  if (!member || member.status !== "approved" || !device ||
      device.status !== "approved" || device.memberId !== member.id) return null;
  return { ...session, member, device, hash };
}
async function requireAdmin(request, env) {
  const session = await currentSession(request, env);
  return session?.member.role === "admin" ? session : null;
}
function validDeviceKey(jwk) {
  return jwk && jwk.kty === "OKP" && jwk.crv === "Ed25519" &&
    typeof jwk.x === "string" && jwk.x.length >= 40;
}
async function verifyDeviceSignature(jwk, challenge, signature) {
  if (!validDeviceKey(jwk) || typeof signature !== "string") return false;
  try {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, key, unb64u(signature), enc.encode(challenge));
  } catch { return false; }
}
async function createSession(env, member, device) {
  const token = randomId(32);
  const hash = await digest(token);
  await put(env, `session:${hash}`, {
    memberId: member.id, deviceId: device.id, expiresAt: Date.now() + 3600_000,
  });
  return token;
}
async function bodyJson(request) {
  const text = await request.text();
  if (text.length > 32_000) throw new Error("Request too large");
  return JSON.parse(text || "{}");
}

export async function handleAuth(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith("/api/")) return null;
  if (request.method !== "POST") return fail("Method not allowed", 405);
  if (!sameOrigin(request, env)) return fail("Origin rejected", 403);

  let body;
  try { body = await bodyJson(request); }
  catch { return fail("Invalid request body"); }

  let cfg;
  try { cfg = config(env); }
  catch { return fail("Authentication is not configured", 503); }

  try {
    if (path === "/api/admin/bootstrap/start") {
      if (request.headers.get("X-Bootstrap-Secret") !== env.ADMIN_BOOTSTRAP_SECRET) return fail("Forbidden", 403);
      if (await get(env, "system:admin-bootstrap-used")) return fail("Administrator already initialized", 409);
      if (typeof body.name !== "string" || body.name.trim().length < 2 || !validDeviceKey(body.devicePublicKey)) {
        return fail("Administrator name and Raspberry Pi device public key are required");
      }
      const flowId = randomId();
      const options = await generateRegistrationOptions({
        rpName: "BLACK-PRIVATE",
        rpID: cfg.rpID,
        userID: enc.encode("black-private-admin"),
        userName: body.name.trim().slice(0, 64),
        attestationType: "none",
        preferredAuthenticatorType: "securityKey",
        authenticatorSelection: { residentKey: "discouraged", userVerification: "required" },
        supportedAlgorithmIDs: [-7, -257],
      });
      await put(env, `flow:register:${flowId}`, {
        challenge: options.challenge, name: body.name.trim().slice(0, 64),
        role: "admin", devicePublicKey: body.devicePublicKey, expiresAt: Date.now() + 300_000,
        bootstrap: true,
      });
      return json({ flowId, options });
    }

    if (path === "/api/admin/bootstrap/finish") {
      if (request.headers.get("X-Bootstrap-Secret") !== env.ADMIN_BOOTSTRAP_SECRET) return fail("Forbidden", 403);
      const flow = await get(env, `flow:register:${body.flowId}`);
      if (!flow || !flow.bootstrap || flow.expiresAt < Date.now() || await get(env, "system:admin-bootstrap-used")) {
        return fail("Bootstrap flow expired or already used", 410);
      }
      const verification = await verifyRegistrationResponse({
        response: body.credential, expectedChallenge: flow.challenge,
        expectedOrigin: cfg.origin, expectedRPID: cfg.rpID,
      });
      if (!verification.verified || !verification.registrationInfo) return fail("Security key verification failed", 401);
      const info = verification.registrationInfo;
      const member = { id: randomId(16), name: flow.name, role: "admin", status: "approved", createdAt: Date.now() };
      const device = { id: randomId(16), memberId: member.id, name: "Administrator Raspberry Pi", publicKey: flow.devicePublicKey, status: "approved", createdAt: Date.now() };
      const credential = { id: info.credential.id, publicKey: info.credential.publicKey, counter: info.credential.counter, transports: info.credential.transports || [] };
      await put(env, `member:${member.id}`, member);
      await put(env, `device:${device.id}`, device);
      await put(env, `credential:${credential.id}`, { ...credential, memberId: member.id });
      await put(env, "system:admin-bootstrap-used", true);
      await del(env, `flow:register:${body.flowId}`);
      const token = await createSession(env, member, device);
      return json({ verified: true, memberId: member.id, deviceId: device.id }, 200, { "Set-Cookie": sessionCookie(token) });
    }

    if (path === "/api/admin/invite") {
      const admin = await requireAdmin(request, env);
      if (!admin) return fail("Administrator authentication required", 401);
      const token = randomId(32), hash = await digest(token);
      await put(env, `invite:${hash}`, { createdBy: admin.member.id, expiresAt: Date.now() + 86_400_000, used: false });
      return json({ inviteToken: token, expiresInSeconds: 86400 });
    }

    if (path === "/api/enroll/start") {
      if (typeof body.inviteToken !== "string" || typeof body.name !== "string" ||
          body.name.trim().length < 2 || !validDeviceKey(body.devicePublicKey)) return fail("Invite, member name, and Raspberry Pi device key are required");
      const inviteHash = await digest(body.inviteToken);
      const invite = await get(env, `invite:${inviteHash}`);
      if (!invite || invite.used || invite.expiresAt < Date.now()) return fail("Invite is invalid, expired, or already used", 403);
      const flowId = randomId();
      const options = await generateRegistrationOptions({
        rpName: "BLACK-PRIVATE", rpID: cfg.rpID,
        userID: enc.encode(randomId(16)), userName: body.name.trim().slice(0, 64),
        attestationType: "none", preferredAuthenticatorType: "securityKey",
        authenticatorSelection: { residentKey: "discouraged", userVerification: "required" },
        supportedAlgorithmIDs: [-7, -257],
      });
      await put(env, `flow:register:${flowId}`, {
        challenge: options.challenge, name: body.name.trim().slice(0, 64),
        role: "member", devicePublicKey: body.devicePublicKey,
        inviteHash, expiresAt: Date.now() + 300_000,
      });
      return json({ flowId, options });
    }

    if (path === "/api/enroll/finish") {
      const flow = await get(env, `flow:register:${body.flowId}`);
      if (!flow || flow.bootstrap || flow.expiresAt < Date.now()) return fail("Enrollment flow expired", 410);
      const invite = await get(env, `invite:${flow.inviteHash}`);
      if (!invite || invite.used || invite.expiresAt < Date.now()) return fail("Invite is no longer valid", 403);
      const verification = await verifyRegistrationResponse({
        response: body.credential, expectedChallenge: flow.challenge,
        expectedOrigin: cfg.origin, expectedRPID: cfg.rpID,
      });
      if (!verification.verified || !verification.registrationInfo) return fail("Security key verification failed", 401);
      const info = verification.registrationInfo;
      const member = { id: randomId(16), name: flow.name, role: "member", status: "pending", createdAt: Date.now() };
      const device = { id: randomId(16), memberId: member.id, name: "Raspberry Pi device", publicKey: flow.devicePublicKey, status: "pending", createdAt: Date.now() };
      const credential = { id: info.credential.id, publicKey: info.credential.publicKey, counter: info.credential.counter, transports: info.credential.transports || [] };
      invite.used = true;
      await put(env, `invite:${flow.inviteHash}`, invite);
      await put(env, `member:${member.id}`, member);
      await put(env, `device:${device.id}`, device);
      await put(env, `credential:${credential.id}`, { ...credential, memberId: member.id });
      await del(env, `flow:register:${body.flowId}`);
      return json({ registered: true, status: "pending", memberId: member.id, deviceId: device.id });
    }

    if (path === "/api/auth/start") {
      if (typeof body.memberId !== "string" || typeof body.deviceId !== "string") return fail("Member and device identifiers are required");
      const member = await get(env, `member:${body.memberId}`);
      const device = await get(env, `device:${body.deviceId}`);
      if (!member || member.status !== "approved" || !device || device.status !== "approved" || device.memberId !== member.id) {
        return fail("Member or Raspberry Pi device is not approved", 403);
      }
      const entries = await store(env, "list", null, null);
      const credentials = entries.entries.filter(([key, value]) => key.startsWith("credential:") && value.memberId === member.id).map(([, value]) => value);
      if (!credentials.length) return fail("No registered security key", 403);
      const flowId = randomId(), deviceChallenge = randomId(32);
      const options = await generateAuthenticationOptions({
        rpID: cfg.rpID,
        userVerification: "required",
        allowCredentials: credentials.map((c) => ({ id: c.id, transports: c.transports })),
      });
      await put(env, `flow:login:${flowId}`, {
        challenge: options.challenge, deviceChallenge, memberId: member.id,
        deviceId: device.id, expiresAt: Date.now() + 180_000,
      });
      return json({ flowId, deviceChallenge, options });
    }

    if (path === "/api/auth/finish") {
      const flow = await get(env, `flow:login:${body.flowId}`);
      if (!flow || flow.expiresAt < Date.now()) return fail("Login challenge expired", 410);
      const member = await get(env, `member:${flow.memberId}`);
      const device = await get(env, `device:${flow.deviceId}`);
      if (!member || member.status !== "approved" || !device || device.status !== "approved") return fail("Member or device revoked", 403);
      const credential = await get(env, `credential:${body.credential?.id}`);
      if (!credential || credential.memberId !== member.id) return fail("Unknown security key", 401);
      const validDevice = await verifyDeviceSignature(device.publicKey, flow.deviceChallenge, body.deviceSignature);
      if (!validDevice) return fail("Raspberry Pi device proof failed", 401);
      const verification = await verifyAuthenticationResponse({
        response: body.credential, expectedChallenge: flow.challenge,
        expectedOrigin: cfg.origin, expectedRPID: cfg.rpID,
        credential: { id: credential.id, publicKey: credential.publicKey, counter: credential.counter, transports: credential.transports },
        requireUserVerification: true,
      });
      if (!verification.verified) return fail("Security key authentication failed", 401);
      credential.counter = verification.authenticationInfo.newCounter;
      await put(env, `credential:${credential.id}`, credential);
      await del(env, `flow:login:${body.flowId}`);
      const token = await createSession(env, member, device);
      return json({ authenticated: true, role: member.role }, 200, { "Set-Cookie": sessionCookie(token) });
    }

    if (path === "/api/admin/members") {
      const admin = await requireAdmin(request, env);
      if (!admin) return fail("Administrator authentication required", 401);
      const members = (await store(env, "list", null, null)).entries
        .filter(([key]) => key.startsWith("member:")).map(([, value]) => value);
      const devices = (await store(env, "list", null, null)).entries
        .filter(([key]) => key.startsWith("device:")).map(([, value]) => value);
      return json({ members, devices });
    }

    if (path === "/api/admin/approve") {
      const admin = await requireAdmin(request, env);
      if (!admin) return fail("Administrator authentication required", 401);
      const member = await get(env, `member:${body.memberId}`);
      const device = await get(env, `device:${body.deviceId}`);
      if (!member || !device || device.memberId !== member.id) return fail("Member or device not found", 404);
      member.status = "approved"; device.status = "approved";
      member.approvedAt = Date.now(); device.approvedAt = Date.now();
      await put(env, `member:${member.id}`, member);
      await put(env, `device:${device.id}`, device);
      return json({ approved: true });
    }

    if (path === "/api/admin/revoke-device") {
      const admin = await requireAdmin(request, env);
      if (!admin) return fail("Administrator authentication required", 401);
      const device = await get(env, `device:${body.deviceId}`);
      if (!device) return fail("Device not found", 404);
      device.status = "revoked"; device.revokedAt = Date.now();
      await put(env, `device:${device.id}`, device);
      return json({ revoked: true });
    }

    if (path === "/api/auth/logout") {
      const token = cookieValue(request, "bp_session");
      if (token) await del(env, `session:${await digest(token)}`);
      return json({ loggedOut: true }, 200, { "Set-Cookie": clearCookie() });
    }

    return fail("Unknown API route", 404);
  } catch (error) {
    console.error("BLACK-PRIVATE auth error:", error?.message || error);
    return fail("Authentication request failed", 500);
  }
}

export async function authorizeRoom(request, env) {
  const session = await currentSession(request, env);
  return Boolean(session);
}
