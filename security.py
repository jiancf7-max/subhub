from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _urlsafe_b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _urlsafe_b64decode(text: str) -> bytes:
    padding = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iter_text, salt, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iter_text)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        expected = _urlsafe_b64decode(digest_text)
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def build_session_token(user: str, secret: str, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {
        "u": user,
        "iat": now,
        "exp": now + int(ttl_seconds),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_text = _urlsafe_b64encode(payload_bytes)
    sig = hmac.new(secret.encode("utf-8"), payload_text.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_text}.{sig}"


def parse_session_token(token: str, secret: str) -> dict[str, Any] | None:
    try:
        payload_text, sig = token.split(".", 1)
    except ValueError:
        return None

    expected_sig = hmac.new(secret.encode("utf-8"), payload_text.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None

    try:
        payload = json.loads(_urlsafe_b64decode(payload_text).decode("utf-8"))
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    exp = int(payload.get("exp", 0) or 0)
    if exp <= int(time.time()):
        return None

    user = str(payload.get("u") or "").strip()
    if not user:
        return None

    return payload
