from __future__ import annotations

import base64
import binascii
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    client_version: str | None = Field(default=None, max_length=32)


class RegisterResponse(BaseModel):
    user_id: str
    salt: str
    api_token: str
    vault_version: int
    updated_at: datetime | None = None


class UploadRequest(BaseModel):
    encrypted_vault: str = Field(min_length=1)
    base_version: int = Field(ge=0)
    client_version: str | None = Field(default=None, max_length=32)

    @field_validator("encrypted_vault")
    @classmethod
    def validate_base64(cls, value: str) -> str:
        try:
            base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError("encrypted_vault must be valid base64") from exc
        return value


class UploadResponse(BaseModel):
    vault_version: int
    updated_at: datetime


class VaultResponse(BaseModel):
    salt: str
    encrypted_vault: str | None = None
    vault_version: int
    updated_at: datetime | None = None
