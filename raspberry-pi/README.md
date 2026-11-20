# Raspberry Pi device agent

The agent runs on the Raspberry Pi itself and keeps an Ed25519 private key in
`~/.black-private/device-ed25519.pem` with file mode 0600. It binds only to
127.0.0.1 and only accepts browser requests from the configured BLACK-PRIVATE
site origin.

## Install

On Raspberry Pi OS:

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv ~/black-private-venv
~/black-private-venv/bin/pip install cryptography
```

Copy `raspberry-pi/device_agent.py` to the Pi, then run:

```bash
BLACK_PRIVATE_ORIGIN=https://dufguugt.jaksj468.workers.dev \
  ~/black-private-venv/bin/python device_agent.py
```

The agent listens on `http://127.0.0.1:8765`. Do not expose this port to the
LAN or the public internet. Keep the key file private and back it up securely;
deleting it means the device must be enrolled again.

## API

- `GET /health`: local agent status.
- `GET /public-key`: device public JWK for enrollment.
- `POST /sign`: signs a short server challenge with the Pi's Ed25519 key.

This proves possession of the agent's private key, not the physical identity of
the board. A software key can be copied. Stronger proof requires compatible
TPM 2.0 or secure-element hardware and a separately verified attestation flow.

## Device enrollment console

After the Worker branch has been deployed to a staging environment and its
required secrets are configured, open:

`https://dufguugt.jaksj468.workers.dev/device.html`

Use the same browser on the Raspberry Pi where the local agent is running.
The console supports first-admin setup, member enrollment, FIDO2 login,
administrator invitations, approvals, and revocation.

## Current implementation boundary

The Worker bundle and Python agent have passed the repository CI dry-run and
syntax checks. This is not a live Cloudflare deployment or a real-hardware
security test. Before production use, test the complete enrollment and login
flow with a real Pi and FIDO2 key, confirm unauthenticated direct WebSocket
requests receive HTTP 401, confirm revoked sessions are rejected, and perform
a security review. Do not deploy this branch to production until those checks
are complete.
