from __future__ import annotations

import json
from pathlib import Path

from .config import APP_DIR, PROFILE_PATH
from .models import ClientProfile


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        APP_DIR.chmod(0o700)
    except OSError:
        pass


def _atomic_write_text(path: Path, content: str) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(content, encoding="utf-8")
    try:
        temp_path.chmod(0o600)
    except OSError:
        pass
    temp_path.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_profile() -> ClientProfile | None:
    if not PROFILE_PATH.exists():
        return None
    raw_payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    return ClientProfile.from_dict(raw_payload)


def save_profile(profile: ClientProfile) -> None:
    ensure_app_dir()
    profile.touch()
    serialized = json.dumps(profile.to_dict(), indent=2, ensure_ascii=False)
    _atomic_write_text(PROFILE_PATH, serialized)
