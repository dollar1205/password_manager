from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets


def generate_salt_b64(num_bytes: int) -> str:
    return base64.b64encode(secrets.token_bytes(num_bytes)).decode("ascii")


def generate_api_token(prefix: str, num_bytes: int) -> str:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")
    return f"{prefix}_{raw}"


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token_hash(token: str, expected_hash: str) -> bool:
    calculated = hash_api_token(token)
    return hmac.compare_digest(calculated, expected_hash)


def decoded_base64_length(data: str) -> int:
    try:
        return len(base64.b64decode(data.encode("ascii"), validate=True))
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Value must be valid base64") from exc
