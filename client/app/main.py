from __future__ import annotations

import argparse
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from .clipboard_guard import run_clipboard_guard
from .config import APP_NAME
from .gui.styles import apply_application_style
from .gui.windows import PasswordManagerWindow


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--clipboard-guard", action="store_true")
    parser.add_argument("--clipboard-digest", default="")
    parser.add_argument("--clipboard-delay", type=int, default=0)
    return parser.parse_known_args(argv)[0]


def main(argv: list[str] | None = None) -> int:
    parsed = _parse_args(list(sys.argv[1:] if argv is None else argv))
    if parsed.clipboard_guard:
        return run_clipboard_guard(
            expected_digest=str(parsed.clipboard_digest or ""),
            delay_seconds=max(1, int(parsed.clipboard_delay or 0)),
        )

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    apply_application_style(app)

    window = PasswordManagerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
