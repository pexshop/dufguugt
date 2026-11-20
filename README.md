# BLACK-PRIVATE

A minimal end-to-end encrypted room chat built on Cloudflare Workers, Durable Objects, and the Web Crypto API.

## Deploy

1. Connect this GitHub repository to Cloudflare Workers Builds.
2. Select **Workers** (not Pages).
3. Build command: leave empty.
4. Deploy command: `npx wrangler deploy`.
5. Root directory: `/`.

The Worker serves `public/index.html` as static assets and routes `/room/<id>` WebSocket connections to a SQLite-backed Durable Object.

## Security model

- The browser creates a random AES-256-GCM key.
- The key is placed in the URL fragment (`#...`), which browsers do not send in HTTP requests.
- Messages are encrypted/decrypted in the browser. The Worker stores and relays ciphertext only.
- Room history is capped at the latest 100 encrypted messages.
- Anyone with the full invitation URL can read and send messages in that room. Share it only with intended participants.

## Limitations

This is an early MVP, not a security-audited messenger. It has no identity verification, forward secrecy, multi-device key management, attachments, or abuse controls. Do not use it for high-risk communications until independently audited. The room key is the access credential; losing it means history cannot be decrypted.
