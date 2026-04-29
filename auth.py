import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Optional

try:
    import bcrypt
except Exception:  # pragma: no cover - bcrypt is optional when plain env password is used.
    bcrypt = None


COOKIE_NAME = "proxy_manager_session"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"
DEFAULT_SESSION_SECONDS = 7 * 24 * 60 * 60

logger = logging.getLogger(__name__)


def auth_enabled() -> bool:
    value = os.getenv("PROXY_MANAGER_AUTH_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "no", "off"}


def configured_username() -> str:
    return os.getenv("PROXY_MANAGER_USERNAME", DEFAULT_USERNAME)


def _configured_password() -> str:
    return os.getenv("PROXY_MANAGER_PASSWORD", DEFAULT_PASSWORD)


def using_default_password() -> bool:
    return (
        auth_enabled()
        and not os.getenv("PROXY_MANAGER_PASSWORD")
        and not os.getenv("PROXY_MANAGER_PASSWORD_HASH")
    )


def session_seconds() -> int:
    try:
        return max(60, int(os.getenv("PROXY_MANAGER_SESSION_SECONDS", str(DEFAULT_SESSION_SECONDS))))
    except ValueError:
        return DEFAULT_SESSION_SECONDS


def _cookie_secure() -> bool:
    value = os.getenv("PROXY_MANAGER_COOKIE_SECURE", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _session_secret() -> bytes:
    secret = os.getenv("PROXY_MANAGER_SESSION_SECRET")
    if secret:
        return secret.encode("utf-8")

    material = (
        configured_username()
        + ":"
        + (os.getenv("PROXY_MANAGER_PASSWORD_HASH") or _configured_password())
        + ":proxy-manager-session-v1"
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def verify_credentials(username: str, password: str) -> bool:
    if not secrets.compare_digest(username or "", configured_username()):
        return False

    password_hash = os.getenv("PROXY_MANAGER_PASSWORD_HASH")
    if password_hash:
        if not bcrypt:
            logger.error("PROXY_MANAGER_PASSWORD_HASH is set, but bcrypt is not installed")
            return False
        try:
            return bool(bcrypt.checkpw((password or "").encode("utf-8"), password_hash.encode("utf-8")))
        except ValueError:
            logger.error("Invalid PROXY_MANAGER_PASSWORD_HASH format")
            return False

    return secrets.compare_digest(password or "", _configured_password())


def create_session_token(username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + session_seconds(),
    }
    payload_part = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_session_secret(), payload_part.encode("ascii"), hashlib.sha256).digest()
    return payload_part + "." + _b64encode(signature)


def verify_session_token(token: Optional[str]) -> Optional[str]:
    if not token or "." not in token:
        return None

    payload_part, signature_part = token.split(".", 1)
    expected = hmac.new(_session_secret(), payload_part.encode("ascii"), hashlib.sha256).digest()
    try:
        actual = _b64decode(signature_part)
    except Exception:
        return None

    if not hmac.compare_digest(actual, expected):
        return None

    try:
        payload = json.loads(_b64decode(payload_part))
    except Exception:
        return None

    if payload.get("sub") != configured_username():
        return None
    if int(payload.get("exp") or 0) < int(time.time()):
        return None

    return str(payload["sub"])


def set_session_cookie(response, username: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        create_session_token(username),
        max_age=session_seconds(),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def current_username(request) -> Optional[str]:
    if not auth_enabled():
        return configured_username()
    return verify_session_token(request.cookies.get(COOKIE_NAME))


def log_startup_warnings() -> None:
    if not auth_enabled():
        logger.warning("Proxy Manager authentication is disabled by PROXY_MANAGER_AUTH_ENABLED")
        return
    if using_default_password():
        logger.warning(
            "Proxy Manager is using the default admin/admin login. "
            "Set PROXY_MANAGER_PASSWORD or PROXY_MANAGER_PASSWORD_HASH before exposing the service."
        )
    if not os.getenv("PROXY_MANAGER_SESSION_SECRET"):
        logger.warning(
            "PROXY_MANAGER_SESSION_SECRET is not set; session tokens are signed with a secret derived from the login password."
        )
