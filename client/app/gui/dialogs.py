from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..config import DEFAULT_GENERATED_PASSWORD_LENGTH
from ..models import VaultEntry
from ..password_generator import PasswordPolicy, generate_password
from ..secure_memory import buffer_from_text, materialize_secret_text, try_lock_bytearray


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._selected_password_text: str | None = None
        self.setWindowTitle("Password Generator")
        self.setModal(True)
        self.resize(420, 220)

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self.length_spin = QSpinBox()
        self.length_spin.setRange(12, 64)
        self.length_spin.setValue(DEFAULT_GENERATED_PASSWORD_LENGTH)
        form.addRow("Length", self.length_spin)

        self.lowercase_checkbox = QCheckBox("Lowercase letters")
        self.lowercase_checkbox.setChecked(True)
        self.uppercase_checkbox = QCheckBox("Uppercase letters")
        self.uppercase_checkbox.setChecked(True)
        self.digits_checkbox = QCheckBox("Digits")
        self.digits_checkbox.setChecked(True)
        self.symbols_checkbox = QCheckBox("Symbols")
        self.symbols_checkbox.setChecked(True)

        layout.addLayout(form)
        layout.addWidget(self.lowercase_checkbox)
        layout.addWidget(self.uppercase_checkbox)
        layout.addWidget(self.digits_checkbox)
        layout.addWidget(self.symbols_checkbox)

        self.password_preview = QLineEdit()
        self.password_preview.setReadOnly(True)
        layout.addWidget(self.password_preview)

        button_row = QHBoxLayout()
        self.regenerate_button = QPushButton("Regenerate")
        self.regenerate_button.clicked.connect(self._generate)
        button_row.addWidget(self.regenerate_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._generate()

    def _policy(self) -> PasswordPolicy:
        return PasswordPolicy(
            length=self.length_spin.value(),
            use_lowercase=self.lowercase_checkbox.isChecked(),
            use_uppercase=self.uppercase_checkbox.isChecked(),
            use_digits=self.digits_checkbox.isChecked(),
            use_symbols=self.symbols_checkbox.isChecked(),
        )

    def _generate(self) -> None:
        try:
            self.password_preview.setText(generate_password(self._policy()))
        except ValueError as exc:
            QMessageBox.warning(self, "Generator Error", str(exc))

    def take_password_text(self) -> str:
        selected_password = self._selected_password_text or ""
        self._selected_password_text = None
        return selected_password

    def _clear_sensitive_fields(self) -> None:
        self.password_preview.clear()

    def accept(self) -> None:
        self._selected_password_text = self.password_preview.text()
        super().accept()

    def reject(self) -> None:
        self._selected_password_text = None
        super().reject()

    def done(self, result: int) -> None:
        self._clear_sensitive_fields()
        super().done(result)

    def closeEvent(self, event) -> None:
        self._clear_sensitive_fields()
        super().closeEvent(event)


class EntryDialog(QDialog):
    def __init__(self, entry: VaultEntry | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self._submitted_data: dict[str, object] | None = None
        self.setWindowTitle("Edit Entry" if entry else "Add Entry")
        self.setModal(True)
        self.resize(520, 420)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.title_edit = QLineEdit(entry.title if entry else "")
        self.username_edit = QLineEdit(entry.username if entry else "")
        existing_password_text = materialize_secret_text(entry.password) if entry else ""
        self.password_edit = QLineEdit(existing_password_text)
        existing_password_text = None
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.url_edit = QLineEdit(entry.url if entry else "")
        self.notes_edit = QTextEdit(entry.notes if entry else "")
        self.notes_edit.setFixedHeight(120)

        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit)
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self._open_generator)
        password_row.addWidget(self.generate_button)

        self.show_password_checkbox = QCheckBox("Show password")
        self.show_password_checkbox.toggled.connect(self._toggle_password_visibility)

        form.addRow("Service", self.title_edit)
        form.addRow("Username", self.username_edit)
        form.addRow("Password", password_row)
        form.addRow("", self.show_password_checkbox)
        form.addRow("URL", self.url_edit)
        form.addRow("Notes", self.notes_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _toggle_password_visibility(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(mode)

    def _open_generator(self) -> None:
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            generated_password = dialog.take_password_text()
            self.password_edit.setText(generated_password)
            generated_password = None

    def _validate_and_accept(self) -> None:
        if not self.title_edit.text().strip():
            QMessageBox.warning(self, "Validation Error", "Service name is required.")
            return
        if not self.password_edit.text():
            QMessageBox.warning(self, "Validation Error", "Password must not be empty.")
            return
        password_text = self.password_edit.text()
        password_buffer = buffer_from_text(password_text)
        try_lock_bytearray(password_buffer)
        self._submitted_data = {
            "title": self.title_edit.text().strip(),
            "username": self.username_edit.text().strip(),
            "password_buffer": password_buffer,
            "url": self.url_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
        }
        password_text = None
        self.accept()

    def take_entry_data(self) -> dict[str, object]:
        submitted_data = self._submitted_data or {
            "title": "",
            "username": "",
            "password_buffer": bytearray(),
            "url": "",
            "notes": "",
        }
        self._submitted_data = None
        return submitted_data

    def _clear_sensitive_fields(self) -> None:
        self.password_edit.clear()
        self.show_password_checkbox.setChecked(False)

    def reject(self) -> None:
        self._submitted_data = None
        super().reject()

    def done(self, result: int) -> None:
        self._clear_sensitive_fields()
        super().done(result)

    def closeEvent(self, event) -> None:
        self._clear_sensitive_fields()
        super().closeEvent(event)


class RevealSecretDialog(QDialog):
    def __init__(self, secret_supplier, timeout_seconds: int, parent: QWidget | None = None):
        super().__init__(parent)
        self._secret_supplier = secret_supplier
        self._secret_loaded = False
        self._remaining_seconds = timeout_seconds
        self.setWindowTitle("Password")
        self.setModal(True)
        self.resize(420, 160)

        layout = QVBoxLayout(self)
        info_label = QLabel("This password will be hidden automatically.")
        layout.addWidget(info_label)

        self.secret_edit = QLineEdit()
        self.secret_edit.setReadOnly(True)
        layout.addWidget(self.secret_edit)

        self.countdown_label = QLabel()
        layout.addWidget(self.countdown_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)
        self._update_countdown()

    def _tick(self) -> None:
        self._remaining_seconds -= 1
        if self._remaining_seconds <= 0:
            self.accept()
            return
        self._update_countdown()

    def _update_countdown(self) -> None:
        self.countdown_label.setText(f"Auto-hide in {self._remaining_seconds} seconds.")

    def showEvent(self, event) -> None:
        if not self._secret_loaded:
            secret_buffer = self._secret_supplier()
            secret_text = materialize_secret_text(secret_buffer)
            self.secret_edit.setText(secret_text)
            secret_text = None
            self._secret_loaded = True
        super().showEvent(event)

    def done(self, result: int) -> None:
        self.timer.stop()
        self.secret_edit.clear()
        self._secret_loaded = False
        super().done(result)

    def closeEvent(self, event) -> None:
        self.secret_edit.clear()
        super().closeEvent(event)
