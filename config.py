from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def _pbkdf2_hash(password: str, salt: str | None = None, iterations: int = 260000) -> str:
    salt = salt or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${iterations}${salt}${encoded}"


@dataclass
class AppConfig:
    host: str = "0.0.0.0"
    port: int = 8850

    admin_user: str = ""
    admin_password_hash: str = ""
    session_secret: str = ""
    session_ttl_seconds: int = 8 * 60 * 60


def load_config(path: Path = CONFIG_PATH) -> AppConfig:
    cfg = AppConfig()
    raw: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded
        except Exception:
            raw = {}

    for key, value in raw.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)

    if not cfg.admin_user:
        env_user = os.environ.get("SUBHUB_ADMIN_USER", "").strip()
        if env_user:
            cfg.admin_user = env_user
        else:
            cfg.admin_user = f"admin_{secrets.token_hex(3)}"
            print(f"[SubHub] Generated initial admin username: {cfg.admin_user}")

    if not cfg.admin_password_hash:
        init_password = os.environ.get("SUBHUB_ADMIN_PASSWORD", "").strip()
        if not init_password:
            init_password = base64.urlsafe_b64encode(secrets.token_bytes(18)).decode("ascii").rstrip("=")
            print(f"[SubHub] Generated initial admin password for user '{cfg.admin_user}': {init_password}")
            print("[SubHub] Please log in and change the credentials immediately.")
        cfg.admin_password_hash = _pbkdf2_hash(init_password)

    if not cfg.session_secret:
        cfg.session_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

    cfg.port = max(1, min(65535, int(cfg.port)))
    cfg.session_ttl_seconds = max(300, min(30 * 24 * 60 * 60, int(cfg.session_ttl_seconds)))

    save_config(cfg, path)
    return cfg


def save_config(cfg: AppConfig, path: Path = CONFIG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")
