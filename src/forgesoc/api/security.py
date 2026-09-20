import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

PBKDF2_ITERATIONS = 600_000
TOKEN_LIFETIME = timedelta(hours=8)


@dataclass(frozen=True, slots=True)
class UserIdentity:
    user_id: str
    username: str
    role: str


class InvalidTokenError(ValueError):
    pass


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (TypeError, ValueError):
        return False


def _secret() -> bytes:
    configured = os.getenv("FORGESOC_SESSION_SECRET")
    if configured:
        return configured.encode()
    return b"forgesoc-local-development-secret-change-before-sharing"


def create_token(identity: UserIdentity, now: datetime | None = None) -> str:
    issued_at = now or datetime.now(UTC)
    payload = {
        "sub": identity.user_id,
        "username": identity.username,
        "role": identity.role,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + TOKEN_LIFETIME).timestamp()),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    signature = hmac.new(_secret(), encoded, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{encoded.decode()}.{encoded_signature}"


def decode_token(token: str, now: datetime | None = None) -> UserIdentity:
    try:
        encoded_text, signature_text = token.split(".", 1)
        encoded = encoded_text.encode()
        supplied_signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        expected = hmac.new(_secret(), encoded, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_signature, expected):
            raise InvalidTokenError("invalid session token")
        payload = json.loads(
            base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        )
        current = now or datetime.now(UTC)
        if int(payload["exp"]) <= int(current.timestamp()):
            raise InvalidTokenError("session token expired")
        return UserIdentity(
            user_id=str(payload["sub"]),
            username=str(payload["username"]),
            role=str(payload["role"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, InvalidTokenError):
            raise
        raise InvalidTokenError("invalid session token") from exc
