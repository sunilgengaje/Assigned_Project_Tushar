# app/middleware/aes_gcm_middleware.py
import os
import json
import base64
from typing import Optional
from starlette.types import ASGIApp, Receive, Scope, Send
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.responses import Response

def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def _unb64(s: Optional[str]) -> Optional[bytes]:
    return base64.b64decode(s) if s is not None else None

def encrypt_json_once(key: bytes, obj) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"data": _b64(nonce + ciphertext), "aad": None}

def decrypt_json_once(key: bytes, data_b64: str, aad_b64: Optional[str] = None):
    combined = base64.b64decode(data_b64)
    if len(combined) < 13:
        raise ValueError("ciphertext too short")
    nonce = combined[:12]
    ciphertext = combined[12:]
    aad = _unb64(aad_b64) if aad_b64 else None
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))

class AESGCMMiddleware:
    """
    ASGI middleware: for requests whose path starts with `secure_prefix`:
      - expects incoming body JSON: {"data":"<base64>", "aad": "<base64 or null>"}
      - decrypts it and replaces the request body with plaintext JSON for downstream handlers
      - after response is produced, captures the response JSON, encrypts it and sends encrypted blob
    """
    def __init__(self, app: ASGIApp, secure_prefix: str = "/secure"):
        self.app = app
        self.secure_prefix = secure_prefix.rstrip("/")

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        from app.core.aes_key_store import aes_key_store
        from app.core.security import decode_token
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith(self.secure_prefix):
            await self.app(scope, receive, send)
            return

        # Extract JWT from Authorization header
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            resp = Response(json.dumps({"detail": "Missing or invalid Authorization header"}), status_code=401, media_type="application/json")
            await resp(scope, receive, send)
            return
        jwt_token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(jwt_token)
            username = payload["sub"]
        except Exception:
            resp = Response(json.dumps({"detail": "Invalid token"}), status_code=401, media_type="application/json")
            await resp(scope, receive, send)
            return
        aes_key = aes_key_store.get_key(username)
        if not aes_key:
            resp = Response(json.dumps({"detail": "No AES key for user/session"}), status_code=401, media_type="application/json")
            await resp(scope, receive, send)
            return

        # consume entire incoming body
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        if not body:
            decrypted_bytes = b"{}"
        else:
            try:
                parsed = json.loads(body.decode("utf-8"))
                data_b64 = parsed.get("data")
                aad_b64 = parsed.get("aad")
                if not data_b64:
                    raise ValueError("missing data")
                plaintext_obj = decrypt_json_once(aes_key, data_b64, aad_b64)
                decrypted_bytes = json.dumps(plaintext_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            except Exception:
                resp = Response(json.dumps({"detail": "invalid encrypted payload"}), status_code=400, media_type="application/json")
                await resp(scope, receive, send)
                return

        # create a new receive that yields decrypted body
        async def _receive():
            return {"type": "http.request", "body": decrypted_bytes, "more_body": False}

        # collect response from downstream
        responder = _ResponseCollector(send)
        await self.app(scope, _receive, responder.send)

        # Decide if response is JSON and encrypt
        content_type = responder.headers.get("content-type", "")
        should_encrypt = content_type.startswith("application/json") or content_type == ""
        final_body = responder.body_bytes
        if should_encrypt:
            try:
                payload_obj = json.loads(final_body.decode("utf-8")) if final_body else {}
            except Exception:
                payload_obj = final_body.decode("utf-8", errors="ignore")
            encrypted = encrypt_json_once(aes_key, payload_obj)
            final_body = json.dumps(encrypted, separators=(",", ":")).encode("utf-8")
            responder.headers["content-type"] = "application/json"
            responder.headers["content-length"] = str(len(final_body))

        await responder.finish_with_body(final_body)

class _ResponseCollector:
    def __init__(self, outer_send: Send):
        self.outer_send = outer_send
        self.status_code = 200
        self._raw_headers = []
        self.headers = {}
        self.body_chunks = []

    @property
    def body_bytes(self) -> bytes:
        return b"".join(self.body_chunks)

    async def send(self, message: dict):
        mtype = message["type"]
        if mtype == "http.response.start":
            self.status_code = message.get("status", 200)
            raw_headers = message.get("headers", [])
            for k, v in raw_headers:
                self._raw_headers.append((k, v))
                name = k.decode("latin-1").lower()
                val = v.decode("latin-1")
                self.headers[name] = val
        elif mtype == "http.response.body":
            body = message.get("body", b"")
            if body:
                self.body_chunks.append(body)

    async def finish_with_body(self, final_body: bytes):
        raw_headers = [(k, v) for (k, v) in self._raw_headers if k.lower() != b"content-length"]
        raw_headers.append((b"content-length", str(len(final_body)).encode("latin-1")))
        if not any(k.lower() == b"content-type" for k, _ in raw_headers):
            raw_headers.append((b"content-type", b"application/json"))
        await self.outer_send({"type": "http.response.start", "status": self.status_code, "headers": raw_headers})
        await self.outer_send({"type": "http.response.body", "body": final_body, "more_body": False})
