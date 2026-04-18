from __future__ import annotations

import ctypes
import hashlib
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QAbstractAnimation, QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..api_client import ApiError, ServerApiClient, VersionConflictError
from ..config import (
    APP_NAME,
    BLOCK_ON_DEBUGGER,
    CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_AUTO_LOCK_SECONDS,
    MIN_MASTER_PASSWORD_LENGTH,
    REVEAL_PASSWORD_SECONDS,
)
from ..crypto import ClientCrypto, CryptoError
from ..models import ClientProfile, VaultEntry, empty_vault_payload, entries_from_vault_payload
from ..secure_memory import (
    buffer_from_text,
    compare_buffers,
    install_emergency_wipe_handlers,
    register_emergency_wipe,
    temporary_secret_text,
    try_lock_bytearray,
    unregister_emergency_wipe,
    wipe_bytearray,
    wipe_many,
)
from ..storage import load_profile, save_profile
from .animations import animate_window_pop, animate_widget_opacity, attach_shadow
from .dialogs import EntryDialog, RevealSecretDialog


class ActivityEventFilter(QObject):
    def __init__(self, on_activity, parent: QObject | None = None):
        super().__init__(parent)
        self._on_activity = on_activity

    def eventFilter(self, _watched, event) -> bool:
        if event.type() in {
            QEvent.Type.KeyPress,
            QEvent.Type.KeyRelease,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.MouseMove,
            QEvent.Type.Wheel,
            QEvent.Type.FocusIn,
            QEvent.Type.TouchBegin,
            QEvent.Type.TouchUpdate,
        }:
            self._on_activity()
        return False


def debugger_present() -> bool:
    if sys.gettrace() is not None:
        return True
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def validate_master_password(password_buffer: bytearray) -> str | None:
    checks = []
    if len(password_buffer) < MIN_MASTER_PASSWORD_LENGTH:
        checks.append(f"at least {MIN_MASTER_PASSWORD_LENGTH} characters")

    if not any(97 <= byte <= 122 for byte in password_buffer):
        checks.append("one lowercase letter")
    if not any(65 <= byte <= 90 for byte in password_buffer):
        checks.append("one uppercase letter")
    if not any(48 <= byte <= 57 for byte in password_buffer):
        checks.append("one digit")
    if not any(not ((48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122)) for byte in password_buffer):
        checks.append("one symbol")

    if checks:
        return "Master password must contain " + ", ".join(checks) + "."
    return None


def normalize_server_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        if cleaned.startswith("localhost") or cleaned.startswith("127.0.0.1"):
            cleaned = f"http://{cleaned}"
        else:
            cleaned = f"https://{cleaned}"
    return cleaned.rstrip("/")


def is_valid_server_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


class PasswordManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        install_emergency_wipe_handlers()
        self.setWindowTitle(APP_NAME)
        self.resize(1180, 760)

        self.crypto = ClientCrypto()
        self.profile = load_profile()
        self.entries: list[VaultEntry] = []
        self.master_key: bytearray | None = None
        self.api_token: bytearray | None = None
        self.current_vault_version = self.profile.local_vault_version if self.profile else 0
        self.offline_mode = False
        self.last_activity = time.monotonic()
        self._clipboard_digest: str | None = None
        self._clipboard_feedback_timer = QTimer(self)
        self._clipboard_feedback_timer.setSingleShot(True)
        self._clipboard_feedback_timer.timeout.connect(self._reset_copy_feedback)
        self._clipboard_clear_timer = QTimer(self)
        self._clipboard_clear_timer.setSingleShot(True)
        self._clipboard_clear_timer.timeout.connect(self._clear_clipboard_if_owned)
        self._debugger_watch_timer = QTimer(self)
        self._debugger_watch_timer.setInterval(2000)
        self._debugger_watch_timer.timeout.connect(self._enforce_runtime_debugger_policy)
        self._animations: list[QAbstractAnimation] = []
        self._window_intro_played = False
        self._emergency_wipe_callback = self._emergency_wipe_session
        register_emergency_wipe(self._emergency_wipe_callback)

        self._build_ui()
        self._apply_visual_effects()
        self._install_activity_monitor()
        self._refresh_profile_state()
        self._update_action_state()
        self._debugger_watch_timer.start()

    def _track_animation(self, animation: QAbstractAnimation | None) -> None:
        if animation is None:
            return
        self._animations.append(animation)
        animation.finished.connect(lambda: self._animations.remove(animation) if animation in self._animations else None)

    def _apply_visual_effects(self) -> None:
        for widget in (
            self.login_card,
            self.vault_header_card,
            self.table,
            self.unlock_button,
            self.create_button,
            self.add_button,
            self.copy_button,
        ):
            attach_shadow(widget)

    def _animate_page(self, page: QWidget) -> None:
        self._track_animation(animate_widget_opacity(page, start=0.72, end=1.0, duration=220))

    def _show_page(self, page: QWidget) -> None:
        self.stack.setCurrentWidget(page)
        self._animate_page(page)

    def _take_secret_from_line_edit(self, line_edit: QLineEdit) -> bytearray:
        raw_text = line_edit.text()
        line_edit.clear()
        secret_buffer = buffer_from_text(raw_text)
        raw_text = None
        try_lock_bytearray(secret_buffer)
        return secret_buffer

    def _clear_auth_fields(self) -> None:
        self.unlock_password_edit.clear()
        self.create_password_edit.clear()
        self.create_confirm_edit.clear()

    def _hash_secret_buffer(self, secret_buffer: bytearray) -> str:
        return hashlib.blake2b(secret_buffer, digest_size=16).hexdigest()

    def _launch_clipboard_guard(self) -> None:
        if not self._clipboard_digest:
            return

        try:
            if getattr(sys, "frozen", False):
                command = [
                    sys.executable,
                    "--clipboard-guard",
                    "--clipboard-digest",
                    self._clipboard_digest,
                    "--clipboard-delay",
                    str(CLIPBOARD_CLEAR_SECONDS),
                ]
            else:
                launcher = Path(__file__).resolve().parents[2] / "main.py"
                command = [
                    sys.executable,
                    str(launcher),
                    "--clipboard-guard",
                    "--clipboard-digest",
                    self._clipboard_digest,
                    "--clipboard-delay",
                    str(CLIPBOARD_CLEAR_SECONDS),
                ]

            popen_kwargs: dict[str, object] = {"close_fds": True}
            if sys.platform.startswith("win") and hasattr(subprocess, "CREATE_NO_WINDOW"):
                popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            subprocess.Popen(command, **popen_kwargs)
        except Exception:
            return

    def _emergency_wipe_session(self) -> None:
        try:
            for entry in self.entries:
                entry.wipe()
            self.entries.clear()
            wipe_many(self.master_key, self.api_token)
            self.master_key = None
            self.api_token = None

            application = QApplication.instance()
            if application is not None and self._clipboard_digest is not None:
                clipboard = application.clipboard()
                clipboard_text = clipboard.text()
                clipboard_digest = hashlib.blake2b(clipboard_text.encode("utf-8"), digest_size=16).hexdigest()
                clipboard_text = None
                if clipboard_digest == self._clipboard_digest:
                    clipboard.clear()
            self._clipboard_digest = None
        except Exception:
            return

    def _mark_copy_feedback(self, copied: bool) -> None:
        feedback_state = "success" if copied else ""
        self.copy_button.setProperty("feedbackState", feedback_state)
        self.copy_button.style().unpolish(self.copy_button)
        self.copy_button.style().polish(self.copy_button)
        self.copy_button.update()
        self.copy_button.setText("Copied" if copied else "Copy Password")

        if copied:
            self._clipboard_feedback_timer.start(1400)

    def _reset_copy_feedback(self) -> None:
        self._mark_copy_feedback(False)

    def _enforce_runtime_debugger_policy(self) -> None:
        if not BLOCK_ON_DEBUGGER:
            return
        if self.master_key is None:
            self._update_action_state()
            return
        if debugger_present():
            self.lock_session("Debugger detected during the active session. Vault locked.")
            QMessageBox.critical(
                self,
                "Security Warning",
                "A debugger was detected while the vault was unlocked. The session was locked and secrets were wiped.",
            )
            return
        self._update_action_state()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._window_intro_played:
            return
        self._window_intro_played = True
        self._track_animation(animate_window_pop(self, duration=240))

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("RootWindow")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(20, 20, 20, 20)
        root_layout.setSpacing(0)

        self.stack = QStackedWidget()
        self.login_page = self._build_login_page()
        self.vault_page = self._build_vault_page()
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.vault_page)
        root_layout.addWidget(self.stack)

        self.setCentralWidget(root)
        self.status_bar = QStatusBar()
        self.status_bar.setObjectName("StatusBar")
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _build_login_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(18)

        title = QLabel("Zero-Knowledge Password Manager")
        title.setObjectName("HeroTitle")
        subtitle = QLabel(
            "Master passwords never leave the desktop client. The server stores only salts and encrypted vault blobs."
        )
        subtitle.setObjectName("HeroSubtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.login_card = QFrame()
        self.login_card.setObjectName("Card")
        card_layout = QVBoxLayout(self.login_card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(18)

        self.auth_tabs = QTabWidget()
        self.unlock_tab = QWidget()
        self.create_tab = QWidget()
        self.auth_tabs.addTab(self.unlock_tab, "Unlock Existing Vault")
        self.auth_tabs.addTab(self.create_tab, "Create New Account")

        unlock_layout = QVBoxLayout(self.unlock_tab)
        unlock_layout.setSpacing(12)
        self.profile_summary_label = QLabel()
        self.profile_summary_label.setWordWrap(True)
        self.profile_summary_label.setObjectName("MutedLabel")
        unlock_layout.addWidget(self.profile_summary_label)

        self.unlock_password_edit = QLineEdit()
        self.unlock_password_edit.setPlaceholderText("Master password")
        self.unlock_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.unlock_password_edit.returnPressed.connect(self.unlock_vault)
        unlock_layout.addWidget(self.unlock_password_edit)

        self.unlock_button = QPushButton("Unlock Vault")
        self.unlock_button.setObjectName("PrimaryButton")
        self.unlock_button.clicked.connect(self.unlock_vault)
        unlock_layout.addWidget(self.unlock_button)

        create_layout = QVBoxLayout(self.create_tab)
        create_layout.setSpacing(12)
        self.server_url_edit = QLineEdit("https://localhost:8443")
        self.server_url_edit.setPlaceholderText("Server URL")
        create_layout.addWidget(self.server_url_edit)

        self.create_password_edit = QLineEdit()
        self.create_password_edit.setPlaceholderText("Master password")
        self.create_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        create_layout.addWidget(self.create_password_edit)

        self.create_confirm_edit = QLineEdit()
        self.create_confirm_edit.setPlaceholderText("Confirm master password")
        self.create_confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.create_confirm_edit.returnPressed.connect(self.register_account)
        create_layout.addWidget(self.create_confirm_edit)

        self.create_button = QPushButton("Register Account")
        self.create_button.setObjectName("PrimaryButton")
        self.create_button.clicked.connect(self.register_account)
        create_layout.addWidget(self.create_button)

        card_layout.addWidget(self.auth_tabs)
        layout.addWidget(self.login_card, 1)

        return page

    def _build_vault_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        self.vault_header_card = QFrame()
        self.vault_header_card.setObjectName("Card")
        header_layout = QVBoxLayout(self.vault_header_card)
        header_layout.setContentsMargins(22, 22, 22, 22)

        section_title = QLabel("Vault")
        section_title.setObjectName("SectionTitle")
        section_subtitle = QLabel(
            "Passwords stay encrypted at rest and are wiped from the active session on lock."
        )
        section_subtitle.setObjectName("MutedLabel")
        header_layout.addWidget(section_title)
        header_layout.addWidget(section_subtitle)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by service, username, URL or notes")
        self.search_edit.textChanged.connect(self._refresh_table)
        toolbar.addWidget(self.search_edit, 1)

        self.add_button = QPushButton("Add")
        self.add_button.setObjectName("PrimaryButton")
        self.add_button.clicked.connect(self.add_entry)
        toolbar.addWidget(self.add_button)

        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.edit_selected_entry)
        toolbar.addWidget(self.edit_button)

        self.delete_button = QPushButton("Delete")
        self.delete_button.setObjectName("DangerButton")
        self.delete_button.clicked.connect(self.delete_selected_entry)
        toolbar.addWidget(self.delete_button)

        self.copy_button = QPushButton("Copy Password")
        self.copy_button.clicked.connect(self.copy_selected_password)
        toolbar.addWidget(self.copy_button)

        self.reveal_button = QPushButton("Reveal")
        self.reveal_button.clicked.connect(self.reveal_selected_password)
        toolbar.addWidget(self.reveal_button)

        self.sync_button = QPushButton("Sync")
        self.sync_button.clicked.connect(self.sync_now)
        toolbar.addWidget(self.sync_button)

        self.lock_button = QPushButton("Lock")
        self.lock_button.clicked.connect(lambda: self.lock_session())
        toolbar.addWidget(self.lock_button)

        header_layout.addLayout(toolbar)
        layout.addWidget(self.vault_header_card)

        self.table = QTableWidget(0, 4)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setMouseTracking(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.verticalScrollBar().setSingleStep(18)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "URL", "Updated"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._update_action_state)
        self.table.itemDoubleClicked.connect(lambda _item: self.edit_selected_entry())
        layout.addWidget(self.table, 1)

        return page

    def _install_activity_monitor(self) -> None:
        application = QApplication.instance()
        if application is None:
            return

        self.activity_filter = ActivityEventFilter(self._mark_activity, self)
        application.installEventFilter(self.activity_filter)

        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.timeout.connect(self._check_inactivity_timeout)
        self.auto_lock_timer.start(5000)

    def _refresh_profile_state(self) -> None:
        if self.profile is None:
            self.profile_summary_label.setText(
                "No local profile found. Register a new account to receive a server-side salt and API token."
            )
            self.auth_tabs.setTabEnabled(0, False)
            self.auth_tabs.setCurrentWidget(self.create_tab)
            self.server_url_edit.setText("https://localhost:8443")
            self.current_vault_version = 0
            return

        self.auth_tabs.setTabEnabled(0, True)
        self.auth_tabs.setCurrentWidget(self.unlock_tab)
        self.profile_summary_label.setText(
            f"Local profile ready for user `{self.profile.user_id}` on {self.profile.server_url}."
        )
        self.server_url_edit.setText(self.profile.server_url)
        self.current_vault_version = self.profile.local_vault_version

    def _mark_activity(self) -> None:
        self.last_activity = time.monotonic()

    def _check_inactivity_timeout(self) -> None:
        if self.master_key is None:
            return

        timeout_seconds = (
            self.profile.lock_timeout_seconds if self.profile else DEFAULT_AUTO_LOCK_SECONDS
        )
        if time.monotonic() - self.last_activity >= timeout_seconds:
            self.lock_session("Vault auto-locked after inactivity.")

    def _block_if_debugger_attached(self, message: str | None = None) -> bool:
        if BLOCK_ON_DEBUGGER and debugger_present():
            QMessageBox.critical(
                self,
                "Security Warning",
                message or "A debugger was detected. Access to secrets is blocked to reduce exposure in memory.",
            )
            return True
        return False

    def register_account(self) -> None:
        if self._block_if_debugger_attached(
            "A debugger was detected. Account registration is blocked to reduce exposure of secrets in memory."
        ):
            self._clear_auth_fields()
            return

        server_url = normalize_server_url(self.server_url_edit.text())
        master_password_buffer = self._take_secret_from_line_edit(self.create_password_edit)
        confirmation_buffer = self._take_secret_from_line_edit(self.create_confirm_edit)

        try:
            if not server_url or not is_valid_server_url(server_url):
                QMessageBox.warning(self, "Validation Error", "Please enter a valid server URL.")
                return

            if not master_password_buffer:
                QMessageBox.warning(self, "Validation Error", "Enter a master password.")
                return

            validation_error = validate_master_password(master_password_buffer)
            if validation_error:
                QMessageBox.warning(self, "Weak Master Password", validation_error)
                return

            if not compare_buffers(master_password_buffer, confirmation_buffer):
                QMessageBox.warning(self, "Validation Error", "Master password confirmation does not match.")
                return

            if self.profile is not None:
                overwrite = QMessageBox.question(
                    self,
                    "Overwrite Local Profile",
                    "Creating a new account will replace the current local profile. Continue?",
                )
                if overwrite != QMessageBox.StandardButton.Yes:
                    return
                self.lock_session(show_message=None)

            api = ServerApiClient(server_url)
            try:
                registration = api.register()
            except ApiError as exc:
                QMessageBox.critical(self, "Registration Failed", str(exc))
                return

            master_key: bytearray | None = None
            session_api_token: bytearray | None = None

            try:
                master_key = self.crypto.derive_master_key(master_password_buffer, registration["salt"])
                wipe_many(master_password_buffer, confirmation_buffer)

                session_api_token = buffer_from_text(str(registration["api_token"]))
                try_lock_bytearray(session_api_token)
                token_nonce_b64, encrypted_api_token_b64 = self.crypto.encrypt_api_token(
                    master_key,
                    session_api_token,
                    str(registration["user_id"]),
                )

                empty_vault_b64 = self.crypto.encrypt_vault(
                    master_key,
                    empty_vault_payload([]),
                    str(registration["user_id"]),
                )

                profile = ClientProfile(
                    user_id=str(registration["user_id"]),
                    server_url=server_url,
                    salt_b64=str(registration["salt"]),
                    api_token_nonce_b64=token_nonce_b64,
                    encrypted_api_token_b64=encrypted_api_token_b64,
                    local_vault_b64=empty_vault_b64,
                    local_vault_version=int(registration["vault_version"]),
                )
                save_profile(profile)

                offline_mode = False
                try:
                    with temporary_secret_text(session_api_token) as api_token_text:
                        upload_result = api.upload_vault(
                            api_token_text,
                            empty_vault_b64,
                            base_version=int(registration["vault_version"]),
                        )
                    profile.local_vault_version = int(upload_result["vault_version"])
                    save_profile(profile)
                except ApiError as exc:
                    offline_mode = True
                    self.status_bar.showMessage(
                        f"Account created, but initial sync failed. Working from local encrypted cache: {exc}",
                        12000,
                    )

                self.profile = profile
                self._refresh_profile_state()
                self._open_session(
                    master_key=master_key,
                    api_token=session_api_token,
                    entries=[],
                    offline_mode=offline_mode,
                )
                master_key = None
                session_api_token = None
            except CryptoError as exc:
                wipe_bytearray(master_key)
                wipe_bytearray(session_api_token)
                QMessageBox.critical(self, "Crypto Error", str(exc))
        finally:
            wipe_many(master_password_buffer, confirmation_buffer)
            self.create_password_edit.clear()
            self.create_confirm_edit.clear()

    def unlock_vault(self) -> None:
        if self.profile is None:
            QMessageBox.warning(self, "No Profile", "Register an account first.")
            return
        if self._block_if_debugger_attached(
            "A debugger was detected. Unlocking is blocked to reduce exposure of secrets in memory."
        ):
            self.unlock_password_edit.clear()
            return

        master_password_buffer = self._take_secret_from_line_edit(self.unlock_password_edit)
        if not master_password_buffer:
            QMessageBox.warning(self, "Validation Error", "Enter your master password.")
            return

        master_key: bytearray | None = None
        api_token: bytearray | None = None

        try:
            master_key = self.crypto.derive_master_key(master_password_buffer, self.profile.salt_b64)
            wipe_bytearray(master_password_buffer)

            api_token = self.crypto.decrypt_api_token(
                master_key,
                self.profile.api_token_nonce_b64,
                self.profile.encrypted_api_token_b64,
                self.profile.user_id,
            )
            encrypted_vault_b64, offline_mode = self._load_latest_encrypted_vault(api_token)

            if encrypted_vault_b64:
                payload = self.crypto.decrypt_vault(master_key, encrypted_vault_b64, self.profile.user_id)
                entries = entries_from_vault_payload(payload)
            else:
                entries = []

            self._open_session(
                master_key=master_key,
                api_token=api_token,
                entries=entries,
                offline_mode=offline_mode,
            )
            master_key = None
            api_token = None
        except (CryptoError, ApiError, ValueError) as exc:
            wipe_bytearray(master_key)
            wipe_bytearray(api_token)
            QMessageBox.critical(self, "Unlock Failed", str(exc))
        finally:
            wipe_bytearray(master_password_buffer)
            self.unlock_password_edit.clear()

    def _load_latest_encrypted_vault(self, api_token: bytearray) -> tuple[str | None, bool]:
        if self.profile is None:
            raise ApiError("Missing local profile.")

        api = ServerApiClient(self.profile.server_url)
        encrypted_vault_b64 = self.profile.local_vault_b64
        offline_mode = False

        try:
            with temporary_secret_text(api_token) as api_token_text:
                remote_vault = api.fetch_vault(api_token_text)
            remote_salt = str(remote_vault["salt"])
            if remote_salt != self.profile.salt_b64:
                raise ApiError("Server salt does not match the local profile.")

            remote_blob = remote_vault.get("encrypted_vault")
            if remote_blob:
                encrypted_vault_b64 = str(remote_blob)
            self.profile.local_vault_b64 = encrypted_vault_b64
            self.profile.local_vault_version = int(remote_vault["vault_version"])
            save_profile(self.profile)
            self.current_vault_version = self.profile.local_vault_version
        except ApiError as exc:
            offline_mode = True
            if encrypted_vault_b64 is None:
                raise ApiError(f"Server is unavailable and no local encrypted cache exists. {exc}") from exc
            self.status_bar.showMessage(
                f"Unlocked from local encrypted cache because the server is unavailable: {exc}",
                12000,
            )

        return encrypted_vault_b64, offline_mode

    def _open_session(
        self,
        *,
        master_key: bytearray,
        api_token: bytearray,
        entries: list[VaultEntry],
        offline_mode: bool,
    ) -> None:
        self._wipe_session_state()
        self.master_key = master_key
        self.api_token = api_token
        try_lock_bytearray(self.master_key)
        try_lock_bytearray(self.api_token)
        self.entries = entries
        self.offline_mode = offline_mode
        self.current_vault_version = self.profile.local_vault_version if self.profile else 0
        self._show_page(self.vault_page)
        self._mark_activity()
        self._refresh_table()
        self._update_action_state()

        if offline_mode:
            self.status_bar.showMessage("Vault unlocked in offline mode from local encrypted cache.", 12000)
        else:
            self.status_bar.showMessage("Vault unlocked.")

    def _wipe_session_state(self) -> None:
        for entry in self.entries:
            entry.wipe()
        self.entries.clear()
        self.table.setRowCount(0)
        wipe_bytearray(self.master_key)
        wipe_bytearray(self.api_token)
        self.master_key = None
        self.api_token = None
        self._clear_clipboard_if_owned(force=True)

    def lock_session(self, show_message: str | None = "Vault locked.") -> None:
        self._wipe_session_state()
        self.offline_mode = False
        self.search_edit.clear()
        self._show_page(self.login_page)
        self._update_action_state()
        if show_message:
            self.status_bar.showMessage(show_message, 8000)

    def _selected_entry(self) -> VaultEntry | None:
        selected_items = self.table.selectedItems()
        if not selected_items:
            return None

        entry_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
        for entry in self.entries:
            if entry.entry_id == entry_id:
                return entry
        return None

    def _refresh_table(self, _text: str | None = None) -> None:
        query = self.search_edit.text().strip()
        self.table.setRowCount(0)

        for entry in sorted(self.entries, key=lambda item: item.title.casefold()):
            if query and not entry.matches(query):
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)

            service_item = QTableWidgetItem(entry.title)
            service_item.setData(Qt.ItemDataRole.UserRole, entry.entry_id)
            username_item = QTableWidgetItem(entry.username)
            url_item = QTableWidgetItem(entry.url)
            updated_item = QTableWidgetItem(entry.updated_at.replace("T", " ").split(".")[0])

            self.table.setItem(row, 0, service_item)
            self.table.setItem(row, 1, username_item)
            self.table.setItem(row, 2, url_item)
            self.table.setItem(row, 3, updated_item)

        self._update_action_state()

    def _update_action_state(self) -> None:
        unlocked = self.master_key is not None
        selected = self._selected_entry() is not None
        debugger_blocked = BLOCK_ON_DEBUGGER and debugger_present()

        self.add_button.setEnabled(unlocked and not debugger_blocked)
        self.edit_button.setEnabled(unlocked and selected and not debugger_blocked)
        self.delete_button.setEnabled(unlocked and selected)
        self.copy_button.setEnabled(unlocked and selected and not debugger_blocked)
        self.reveal_button.setEnabled(unlocked and selected and not debugger_blocked)
        self.sync_button.setEnabled(unlocked and not debugger_blocked)
        self.lock_button.setEnabled(unlocked)
        self.unlock_button.setEnabled((self.profile is not None) and not debugger_blocked)
        self.create_button.setEnabled(not debugger_blocked)

    def add_entry(self) -> None:
        if self._block_if_debugger_attached(
            "A debugger was detected. Editing secrets is blocked while the debugger is attached."
        ):
            return
        dialog = EntryDialog(parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return

        data = dialog.take_entry_data()
        self.entries.append(VaultEntry.create(**data))
        self._persist_and_refresh("Entry added.")

    def edit_selected_entry(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        if self._block_if_debugger_attached(
            "A debugger was detected. Editing secrets is blocked while the debugger is attached."
        ):
            return

        dialog = EntryDialog(entry=entry, parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return

        entry.update_from_buffer(**dialog.take_entry_data())
        self._persist_and_refresh("Entry updated.")

    def delete_selected_entry(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return

        choice = QMessageBox.question(
            self,
            "Delete Entry",
            f"Delete '{entry.title}' from the vault?",
        )
        if choice != QMessageBox.StandardButton.Yes:
            return

        self.entries = [item for item in self.entries if item.entry_id != entry.entry_id]
        entry.wipe()
        self._persist_and_refresh("Entry deleted.")

    def _persist_and_refresh(self, success_message: str) -> None:
        try:
            persisted = self.persist_vault()
        except CryptoError as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))
            return

        self._refresh_table()
        if persisted:
            self.status_bar.showMessage(success_message, 6000)

    def persist_vault(self) -> bool:
        if self.profile is None or self.master_key is None or self.api_token is None:
            raise CryptoError("Cannot persist the vault without an active session.")

        encrypted_vault_b64 = self.crypto.encrypt_vault(
            self.master_key,
            empty_vault_payload(self.entries),
            self.profile.user_id,
        )

        self.profile.local_vault_b64 = encrypted_vault_b64
        save_profile(self.profile)

        api = ServerApiClient(self.profile.server_url)
        try:
            with temporary_secret_text(self.api_token) as api_token_text:
                result = api.upload_vault(
                    api_token_text,
                    encrypted_vault_b64,
                    base_version=self.current_vault_version,
                )
            self.current_vault_version = int(result["vault_version"])
            self.profile.local_vault_version = self.current_vault_version
            save_profile(self.profile)
            self.offline_mode = False
            return True
        except VersionConflictError as exc:
            self.offline_mode = True
            QMessageBox.warning(
                self,
                "Version Conflict",
                f"{exc} Current server version: {exc.current_version}. Reload from the server before saving again.",
            )
            return False
        except ApiError as exc:
            self.offline_mode = True
            self.status_bar.showMessage(
                f"Saved to local encrypted cache only. Sync pending: {exc}",
                10000,
            )
            return True

    def copy_selected_password(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        if self._block_if_debugger_attached(
            "A debugger was detected. Copying secrets to the clipboard is blocked while the debugger is attached."
        ):
            return

        clipboard = QApplication.clipboard()
        with temporary_secret_text(entry.password) as password_text:
            clipboard.setText(password_text)
        self._clipboard_digest = self._hash_secret_buffer(entry.password)
        self._clipboard_clear_timer.start(CLIPBOARD_CLEAR_SECONDS * 1000)
        self._launch_clipboard_guard()
        self._mark_copy_feedback(True)
        self.status_bar.showMessage(
            f"Password copied. Clipboard will clear in {CLIPBOARD_CLEAR_SECONDS} seconds.",
            8000,
        )

    def _clear_clipboard_if_owned(self, force: bool = False) -> None:
        if self._clipboard_digest is None and not force:
            return

        clipboard = QApplication.clipboard()
        cleared = False
        if force:
            clipboard.clear()
            cleared = True
        else:
            clipboard_text = clipboard.text()
            clipboard_digest = hashlib.blake2b(clipboard_text.encode("utf-8"), digest_size=16).hexdigest()
            clipboard_text = None
            if clipboard_digest == self._clipboard_digest:
                clipboard.clear()
                cleared = True
        self._clipboard_digest = None
        self._clipboard_clear_timer.stop()
        if cleared:
            self.status_bar.showMessage("Clipboard cleared.", 4000)
        self._reset_copy_feedback()

    def reveal_selected_password(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        if self._block_if_debugger_attached(
            "A debugger was detected. Password reveal is blocked while the debugger is attached."
        ):
            return

        dialog = RevealSecretDialog(
            secret_supplier=lambda selected_entry=entry: selected_entry.password,
            timeout_seconds=REVEAL_PASSWORD_SECONDS,
            parent=self,
        )
        dialog.exec()

    def sync_now(self) -> None:
        if self.profile is None or self.api_token is None or self.master_key is None:
            return
        if self._block_if_debugger_attached(
            "A debugger was detected. Sync is blocked while secrets are exposed to the debugger."
        ):
            return

        api = ServerApiClient(self.profile.server_url)

        with temporary_secret_text(self.api_token) as token:
            if self.offline_mode and self.profile.local_vault_b64:
                try:
                    result = api.upload_vault(
                        token,
                        self.profile.local_vault_b64,
                        base_version=self.current_vault_version,
                    )
                    self.current_vault_version = int(result["vault_version"])
                    self.profile.local_vault_version = self.current_vault_version
                    save_profile(self.profile)
                    self.offline_mode = False
                except VersionConflictError as exc:
                    reload_remote = QMessageBox.question(
                        self,
                        "Sync Conflict",
                        f"{exc} The server has a newer version. Reload the remote vault and discard unsynced local cache?",
                    )
                    if reload_remote != QMessageBox.StandardButton.Yes:
                        return
                except ApiError as exc:
                    QMessageBox.warning(self, "Sync Failed", str(exc))
                    return

            try:
                remote_vault = api.fetch_vault(token)
                remote_blob = remote_vault.get("encrypted_vault")
                self.profile.local_vault_version = int(remote_vault["vault_version"])
                self.current_vault_version = self.profile.local_vault_version

                if remote_blob:
                    remote_blob = str(remote_blob)
                    payload = self.crypto.decrypt_vault(self.master_key, remote_blob, self.profile.user_id)
                    self.entries = entries_from_vault_payload(payload)
                    self.profile.local_vault_b64 = remote_blob
                else:
                    self.entries = []
                    self.profile.local_vault_b64 = None

                save_profile(self.profile)
                self._refresh_table()

                self.offline_mode = False
                self.status_bar.showMessage("Vault synchronized with the server.", 8000)
            except (ApiError, CryptoError, ValueError) as exc:
                QMessageBox.warning(self, "Sync Failed", str(exc))

    def closeEvent(self, event) -> None:
        unregister_emergency_wipe(self._emergency_wipe_callback)
        self.lock_session(show_message=None)
        super().closeEvent(event)
