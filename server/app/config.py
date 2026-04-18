from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zero-Knowledge Password Manager API"
    app_version: str = "1.0.0"
    database_url: str = "sqlite:///./server/password_manager.db"
    require_https: bool = True
    allow_insecure_localhost: bool = True
    token_prefix: str = "zkm"
    token_bytes: int = 32
    salt_bytes: int = 32
    max_vault_bytes: int = 1_048_576
    default_rate_limit: str = "60/minute"
    register_rate_limit: str = "5/minute"
    upload_rate_limit: str = "30/minute"
    vault_rate_limit: str = "30/minute"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PM_",
        case_sensitive=False,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
