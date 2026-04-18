from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from .config import DEFAULT_AUTO_LOCK_SECONDS, PROFILE_SCHEMA_VERSION, VAULT_SCHEMA_VERSION
from .secure_memory import buffer_from_text, materialize_secret_text, try_lock_bytearray, wipe_bytearray


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class VaultEntry:
    entry_id: str
    title: str
    username: str
    password: bytearray = field(repr=False)
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory=utc_timestamp)
    updated_at: str = field(default_factory=utc_timestamp)

    @classmethod
    def create(
        cls,
        *,
        title: str,
        username: str,
        password_buffer: bytearray,
        url: str = "",
        notes: str = "",
    ) -> "VaultEntry":
        try_lock_bytearray(password_buffer)
        return cls(
            entry_id=uuid4().hex,
            title=title,
            username=username,
            password=password_buffer,
            url=url,
            notes=notes,
        )

    @classmethod
    def from_payload(cls, payload: dict[str, str]) -> "VaultEntry":
        password_text = payload.get("password", "")
        password_buffer = buffer_from_text(password_text)
        try_lock_bytearray(password_buffer)
        payload["password"] = ""
        password_text = None
        return cls(
            entry_id=payload.get("id") or uuid4().hex,
            title=payload.get("title", ""),
            username=payload.get("username", ""),
            password=password_buffer,
            url=payload.get("url", ""),
            notes=payload.get("notes", ""),
            created_at=payload.get("created_at", utc_timestamp()),
            updated_at=payload.get("updated_at", utc_timestamp()),
        )

    def update_from_buffer(
        self,
        *,
        title: str,
        username: str,
        password_buffer: bytearray,
        url: str,
        notes: str,
    ) -> None:
        wipe_bytearray(self.password)
        try_lock_bytearray(password_buffer)
        self.title = title
        self.username = username
        self.password = password_buffer
        self.url = url
        self.notes = notes
        self.updated_at = utc_timestamp()

    def to_payload(self) -> dict[str, str]:
        password_text = materialize_secret_text(self.password)
        return {
            "id": self.entry_id,
            "title": self.title,
            "username": self.username,
            "password": password_text,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def matches(self, query: str) -> bool:
        normalized = query.casefold()
        searchable = " ".join([self.title, self.username, self.url, self.notes]).casefold()
        return normalized in searchable

    def wipe(self) -> None:
        wipe_bytearray(self.password)
        self.title = ""
        self.username = ""
        self.url = ""
        self.notes = ""


@dataclass(slots=True)
class ClientProfile:
    user_id: str
    server_url: str
    salt_b64: str
    api_token_nonce_b64: str
    encrypted_api_token_b64: str
    local_vault_b64: str | None = None
    local_vault_version: int = 0
    lock_timeout_seconds: int = DEFAULT_AUTO_LOCK_SECONDS
    tls_cert_sha256: str | None = None
    schema_version: int = PROFILE_SCHEMA_VERSION
    created_at: str = field(default_factory=utc_timestamp)
    updated_at: str = field(default_factory=utc_timestamp)

    def touch(self) -> None:
        self.updated_at = utc_timestamp()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "user_id": self.user_id,
            "server_url": self.server_url,
            "salt_b64": self.salt_b64,
            "api_token_nonce_b64": self.api_token_nonce_b64,
            "encrypted_api_token_b64": self.encrypted_api_token_b64,
            "local_vault_b64": self.local_vault_b64,
            "local_vault_version": self.local_vault_version,
            "lock_timeout_seconds": self.lock_timeout_seconds,
            "tls_cert_sha256": self.tls_cert_sha256,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ClientProfile":
        return cls(
            schema_version=int(payload.get("schema_version", PROFILE_SCHEMA_VERSION)),
            user_id=str(payload["user_id"]),
            server_url=str(payload["server_url"]),
            salt_b64=str(payload["salt_b64"]),
            api_token_nonce_b64=str(payload["api_token_nonce_b64"]),
            encrypted_api_token_b64=str(payload["encrypted_api_token_b64"]),
            local_vault_b64=str(payload["local_vault_b64"]) if payload.get("local_vault_b64") else None,
            local_vault_version=int(payload.get("local_vault_version", 0)),
            lock_timeout_seconds=int(payload.get("lock_timeout_seconds", DEFAULT_AUTO_LOCK_SECONDS)),
            tls_cert_sha256=str(payload["tls_cert_sha256"]) if payload.get("tls_cert_sha256") else None,
            created_at=str(payload.get("created_at", utc_timestamp())),
            updated_at=str(payload.get("updated_at", utc_timestamp())),
        )


def empty_vault_payload(entries: list[VaultEntry] | None = None) -> dict[str, object]:
    return {
        "schema_version": VAULT_SCHEMA_VERSION,
        "updated_at": utc_timestamp(),
        "entries": [entry.to_payload() for entry in (entries or [])],
    }


def entries_from_vault_payload(payload: dict[str, object]) -> list[VaultEntry]:
    raw_entries = payload.get("entries", [])
    if not isinstance(raw_entries, list):
        raise ValueError("Vault payload must contain an entries list.")
    return [VaultEntry.from_payload(item) for item in raw_entries if isinstance(item, dict)]
