from __future__ import annotations

import hashlib

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication


def run_clipboard_guard(*, expected_digest: str, delay_seconds: int) -> int:
    if not expected_digest:
        return 1

    application = QApplication.instance()
    owns_application = application is None
    if application is None:
        application = QApplication(["clipboard-guard"])
    application.setQuitOnLastWindowClosed(False)

    clipboard = application.clipboard()

    def clear_if_owned() -> None:
        try:
            clipboard_text = clipboard.text()
            clipboard_digest = hashlib.blake2b(clipboard_text.encode("utf-8"), digest_size=16).hexdigest()
            clipboard_text = None
            if clipboard_digest == expected_digest:
                clipboard.clear()
        finally:
            if owns_application:
                application.quit()

    QTimer.singleShot(max(1, delay_seconds) * 1000, clear_if_owned)
    return application.exec() if owns_application else 0
