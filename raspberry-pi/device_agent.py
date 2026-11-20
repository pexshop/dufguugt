#!/usr/bin/env python3
"""BLACK-PRIVATE local Raspberry Pi device-key agent.

Run this on the Raspberry Pi itself. It binds only to loopback and only
accepts browser requests from the configured BLACK-PRIVATE origin.
"""
import base64
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ORIGIN = os.environ.get("BLACK_PRIVATE_ORIGIN", "https://dufguugt.jaksj468.workers.dev")
KEY_DIR = Path.home() / ".black-private"
KEY_FILE = KEY_DIR / "device-ed25519.pem"
HOST = "127.0.0.1"
PORT = 8765


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_or_create_key():
    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        raw = KEY_FILE.read_bytes()
        return serialization.load_pem_private_key(raw, password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return key


PRIVATE_KEY = load_or_create_key()


def public_jwk():
    raw = PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw), "ext": True}


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        origin = self.headers.get("Origin")
        if origin != ORIGIN:
            self.send_error(403, "Origin rejected")
            return False
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "300")
        return True

    def do_OPTIONS(self):
        if self.headers.get("Origin") != ORIGIN:
            self.send_error(403, "Origin rejected")
            return
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _send_json(self, payload, status=200):
        self.send_response(status)
        if not self._cors():
            return
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        if self.path == "/public-key":
            self._send_json({"publicKey": public_jwk()})
        elif self.path == "/health":
            self._send_json({"status": "ok", "service": "BLACK-PRIVATE Pi agent"})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/sign":
            self._send_json({"error": "not found"}, 404)
            return
        if self.headers.get("Origin") != ORIGIN:
            self.send_error(403, "Origin rejected")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                raise ValueError("invalid request size")
            body = json.loads(self.rfile.read(length))
            challenge = body.get("challenge")
            if not isinstance(challenge, str) or not challenge or len(challenge) > 512:
                raise ValueError("invalid challenge")
            signature = PRIVATE_KEY.sign(challenge.encode("utf-8"))
            self._send_json({"signature": b64url(signature)})
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def log_message(self, fmt, *args):
        print("BLACK-PRIVATE Pi agent:", fmt % args)


if __name__ == "__main__":
    print(f"BLACK-PRIVATE device agent listening on http://{HOST}:{PORT}")
    print(f"Allowed website origin: {ORIGIN}")
    HTTPServer((HOST, PORT), Handler).serve_forever()
