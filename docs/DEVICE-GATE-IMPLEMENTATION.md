# BLACK-PRIVATE Raspberry Pi Device Gate

## Status

Design and implementation work is in progress on `feature/raspberry-pi-device-gate`.
This document is a specification, not evidence that the gate is deployed or security-tested.

## Admission policy

A member needs all of the following:
1. A Raspberry Pi of a supported model running the BLACK-PRIVATE device agent.
2. A per-device cryptographic key pair generated on that device.
3. A registered FIDO2/WebAuthn authenticator belonging to that member.
4. Explicit administrator approval for the member and device.

Every room WebSocket upgrade must be authorized by the Worker before the ChatRoom Durable Object accepts it. The browser UI is never the security boundary.

## Important hardware limitation

Most Raspberry Pi boards do not provide a universal, built-in, remotely verifiable hardware identity or secure-element attestation. A software-generated device key proves possession of that key, not the physical model of the computer. A copied software key could be used elsewhere. Do not describe this as cryptographic proof that the client is physically a Raspberry Pi.

For stronger assurance, support a TPM 2.0 or secure element with non-exportable keys and verified attestation on compatible hardware. This must be an explicit stronger tier, not assumed for every Pi model.

## Planned server components

- WebAuthn registration and authentication with a maintained FIDO2 implementation.
- One-time, short-lived enrollment invitations; no public self-service administrator enrollment.
- Persistent records for members, WebAuthn credentials, device public keys, enrollment challenges, sessions, and revocation state.
- Signed, short-lived device challenges to prove possession of each enrolled device key.
- Admin-only approval and immediate revocation.
- Session verification and origin checks before every WebSocket upgrade.
- Rate limits, CSRF protection for state-changing browser routes, and audit events.

## Key separation

The Raspberry Pi device key identifies an enrolled device. The member's WebAuthn security key authenticates the human member. Neither replaces the other. The administrator must also authenticate with their own WebAuthn credential.

## Existing chat encryption caveat

The current chat app places the AES-GCM room key in the invitation URL fragment. Anyone who obtains the complete invitation can decrypt messages, regardless of device admission. Device admission does not fix invitation-key sharing or provide forward secrecy. A separate member/device-bound key distribution design and security review are required before claiming Signal-like security.

## Deployment safety

Do not deploy this branch or enable admission claims until:
- WebAuthn flows are tested on supported browsers and authenticators.
- Device enrollment and challenge signatures are tested.
- Unauthenticated direct WebSocket upgrades are rejected.
- Revoked sessions are rejected immediately.
- Existing encrypted chat behavior is regression-tested.
- Required Cloudflare bindings and secrets are configured.
- A production security review is completed.
