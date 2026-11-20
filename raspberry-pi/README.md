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

## Current implementation boundary

The Worker endpoints and local agent are backend components. The public chat
page has not yet been updated with enrollment/login controls, so end-to-end
member onboarding is not ready. Do not deploy this branch to production yet.
