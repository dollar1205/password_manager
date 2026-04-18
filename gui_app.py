

import customtkinter as ctk
from tkinter import messagebox, simpledialog
import os
import json
import base64
import hashlib
import secrets
import string
import threading
import time
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
import hmac
import base64
import shutil
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHash
from argon2.low_level import hash_secret_raw, Type
import sys

# --- Security core (merged from gui_app_secure.py) ---
CLIPBOARD_TIMEOUT = 10
PASSWORD_SHOW_TIMEOUT = 5
LOGIN_ATTEMPTS = 3
LOGIN_ATTEMPT_BACKOFF = [1, 2, 4]
MIN_PASSWORD_LENGTH = 8
VAULT_FORMAT_VERSION = 2

# optional libs
try:
    import psutil
except Exception:
    psutil = None

try:
    from zxcvbn import zxcvbn
except Exception:
    zxcvbn = None


class SecurityUtils:
    @staticmethod
    def is_debugger_present() -> bool:
        return sys.gettrace() is not None

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        # Prefer zxcvbn if available for a better score
        if zxcvbn is not None:
            try:
                res = zxcvbn(password)
                score = res.get('score', 0)
                if score < 3:
                    return False, "Слабый пароль: используйте длиннее и добавьте цифры/символы"
                return True, "OK"
            except Exception:
                pass
        # Fallback simple checks
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Минимум {MIN_PASSWORD_LENGTH} символов"
        if not any(c.isupper() for c in password):
            return False, "Требуется минимум одна заглавная буква"
        if not any(c.islower() for c in password):
            return False, "Требуется минимум одна строчная буква"
        if not any(c.isdigit() for c in password):
            return False, "Требуется минимум одна цифра"
        return True, "OK"


class CryptoManager:
    def __init__(self):
        self.ph = PasswordHasher()
        self._ensure_crypto_files()

    def _ensure_crypto_files(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        if not HMAC_KEY_FILE.exists():
            HMAC_KEY_FILE.write_bytes(os.urandom(32))
            try:
                HMAC_KEY_FILE.chmod(0o600)
            except Exception:
                pass

    def _get_salt(self) -> bytes:
        if SALT_FILE.exists():
            return SALT_FILE.read_bytes()
        salt = os.urandom(32)
        SALT_FILE.write_bytes(salt)
        try:
            SALT_FILE.chmod(0o600)
        except Exception:
            pass
        return salt

    def _get_hmac_key(self) -> bytes:
        # Ensure HMAC key file exists — create it lazily if missing (handles cases when user deleted files)
        try:
            if not HMAC_KEY_FILE.exists():
                try:
                    DATA_DIR.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                HMAC_KEY_FILE.write_bytes(os.urandom(32))
                try:
                    HMAC_KEY_FILE.chmod(0o600)
                except Exception:
                    pass
            return HMAC_KEY_FILE.read_bytes()
        except Exception as e:
            raise RuntimeError(f"Не удалось получить HMAC ключ: {e}")

    def derive_key_argon2(self, master_password: str) -> bytes:
        salt = self._get_salt()
        try:
            # Deterministically derive a 32-byte key with Argon2id (hash_secret_raw)
            # Parameters tuned for moderate hardness; can be adjusted per platform
            key = hash_secret_raw(master_password.encode('utf-8'), salt, time_cost=2, memory_cost=2**15, parallelism=1, hash_len=32, type=Type.ID)
        except Exception as e:
            raise RuntimeError(f"Ошибка Argon2: {e}")
        return base64.urlsafe_b64encode(key)

    def verify_password_argon2(self, password: str, hash_obj: str) -> bool:
        try:
            self.ph.verify(hash_obj, password)
            return True
        except (VerificationError, InvalidHash):
            return False

    def create_fernet_key(self) -> bytes:
        return Fernet.generate_key()

    def compute_hmac(self, data: bytes) -> str:
        key = self._get_hmac_key()
        h = hmac.new(key, data, hashlib.sha256)
        return base64.b64encode(h.digest()).decode()

    def verify_hmac(self, data: bytes, hmac_str: str) -> bool:
        try:
            key = self._get_hmac_key()
            h = hmac.new(key, data, hashlib.sha256)
            expected = base64.b64encode(h.digest()).decode()
            return hmac.compare_digest(expected, hmac_str)
        except Exception:
            return False


class SessionManager:
    def __init__(self, timeout: int | None = None):
        if timeout is None:
            timeout = SESSION_TIMEOUT
        self.timeout = timeout
        self.last_activity = time.time()
        self.is_active = True
        self._lock = threading.Lock()
        self._timer_thread = None

    def update_activity(self):
        with self._lock:
            self.last_activity = time.time()

    def check_timeout(self) -> bool:
        with self._lock:
            return time.time() - self.last_activity > self.timeout

    def start_timeout_checker(self, on_timeout_callback):
        def checker():
            while self.is_active:
                time.sleep(10)
                if self.check_timeout():
                    on_timeout_callback()
                    break
        self._timer_thread = threading.Thread(target=checker, daemon=True)
        self._timer_thread.start()

    def stop(self):
        self.is_active = False


class PasswordManagerCore:
    def __init__(self):
        self.crypto = CryptoManager()
        self.fernet = None
        self.master_hash = None
        self.vault = {}
        self.session = SessionManager()
        self._login_attempts = 0
        self._debugger_detected = False
        if SecurityUtils.is_debugger_present():
            self._debugger_detected = True

    def is_initialized(self) -> bool:
        return DATA_FILE.exists()

    def initialize(self, master_password: str) -> tuple[bool, str]:
        if self.is_initialized():
            return False, "Уже инициализировано"
        valid, msg = SecurityUtils.validate_password_strength(master_password)
        if not valid:
            return False, msg
        try:
            self.master_hash = self.crypto.ph.hash(master_password)
            key = self.crypto.derive_key_argon2(master_password)
            self.fernet = Fernet(key)
            self.vault = {"_format_version": VAULT_FORMAT_VERSION, "_created": datetime.now().isoformat(), "_master_hash": self.master_hash}
            self._save_vault()
            return True, "Хранилище успешно создано!"
        except Exception as e:
            return False, f"Ошибка при создании: {e}"

    def unlock(self, master_password: str) -> bool:
        if self._login_attempts >= LOGIN_ATTEMPTS:
            return False
        try:
            encrypted_data = DATA_FILE.read_bytes()
            self._verify_vault_integrity(encrypted_data)
            # quick preview requires no key yet, use stored master hash for verification
            if not DATA_FILE.exists():
                return False
            vault_preview = json.loads(Fernet(self.crypto.derive_key_argon2(master_password)).decrypt(encrypted_data).decode()) if False else None
        except Exception:
            # try regular verify
            pass
        try:
            encrypted_data = DATA_FILE.read_bytes()
            self._verify_vault_integrity(encrypted_data)
            # decrypt with derived key
            key = self.crypto.derive_key_argon2(master_password)
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data)
            vault_preview = json.loads(decrypted.decode())
            stored_hash = vault_preview.get("_master_hash")
            if not stored_hash:
                return False
            if not self.crypto.verify_password_argon2(master_password, stored_hash):
                self._login_attempts += 1
                return False
            self.fernet = Fernet(key)
            self.master_hash = stored_hash
            self._login_attempts = 0
            if self._load_vault():
                self.session.update_activity()
                return True
            return False
        except InvalidToken:
            self._login_attempts += 1
            return False
        except Exception:
            return False

    def _verify_vault_integrity(self, encrypted_data: bytes):
        hmac_file = DATA_DIR / "vault.hmac"
        if hmac_file.exists():
            stored_hmac = hmac_file.read_text().strip()
            if not self.crypto.verify_hmac(encrypted_data, stored_hmac):
                raise ValueError("Целостность хранилища нарушена")

    def _load_vault(self) -> bool:
        if not DATA_FILE.exists():
            self.vault = {"_format_version": VAULT_FORMAT_VERSION, "_created": datetime.now().isoformat()}
            return True
        try:
            encrypted_data = DATA_FILE.read_bytes()
            self._verify_vault_integrity(encrypted_data)
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.vault = json.loads(decrypted_data.decode())
            return True
        except InvalidToken:
            return False
        except Exception:
            return False

    def _save_vault(self):
        # ensure data directory exists before writing files
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        if DATA_FILE.exists():
            backup_file = BACKUP_DIR / f"vault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
            try:
                shutil.copy2(DATA_FILE, backup_file)
            except Exception:
                pass
            backups = sorted(BACKUP_DIR.glob("vault_*.enc"))
            for old_backup in backups[:-10]:
                try:
                    old_backup.unlink()
                except Exception:
                    pass
        data = json.dumps(self.vault, ensure_ascii=False, indent=2)
        encrypted_data = self.fernet.encrypt(data.encode())
        temp_file = DATA_FILE.with_suffix('.tmp')
        temp_file.write_bytes(encrypted_data)
        temp_file.replace(DATA_FILE)
        hmac_value = self.crypto.compute_hmac(encrypted_data)
        try:
            (DATA_DIR / "vault.hmac").write_text(hmac_value)
        except Exception:
            # best effort: if we can't write hmac, still keep the vault file
            pass
        try:
            DATA_FILE.chmod(0o600)
        except Exception:
            pass

    def lock(self):
        self.fernet = None
        self.master_hash = None
        self.vault = {}
        self._clear_clipboard()
        self.session.stop()

    def _clear_clipboard(self):
        try:
            import pyperclip
            current = pyperclip.paste()
            if current and len(current) < 256:
                pyperclip.copy("")
        except Exception:
            pass

    def add_password(self, service: str, username: str, password: str, notes: str = ""):
        self.session.update_activity()
        # ensure vault is unlocked (we need self.fernet to save the vault)
        if self.fernet is None:
            raise RuntimeError("Хранилище не разблокировано")
        # generate a fresh fernet key and use it to encrypt the password
        key = self.crypto.create_fernet_key()
        pwd_fernet = Fernet(key)
        encrypted_pwd = pwd_fernet.encrypt(password.encode()).decode()
        key_for_pwd = key.decode()
        self.vault[service] = {"username": username, "password": encrypted_pwd, "password_key": key_for_pwd, "notes": notes, "created": datetime.now().isoformat(), "modified": datetime.now().isoformat()}
        self._save_vault()

    def get_password(self, service: str) -> dict | None:
        self.session.update_activity()
        if service not in self.vault or service.startswith("_"):
            return None
        entry = self.vault[service]
        try:
            pwd_fernet = Fernet(entry["password_key"].encode())
            decrypted_pwd = pwd_fernet.decrypt(entry["password"].encode()).decode()
            return {"username": entry.get("username"), "password": decrypted_pwd, "notes": entry.get("notes"), "created": entry.get("created"), "modified": entry.get("modified")}
        except Exception:
            return None

    def delete_password(self, service: str) -> bool:
        self.session.update_activity()
        if service in self.vault and not service.startswith("_"):
            del self.vault[service]
            self._save_vault()
            return True
        return False

    def list_services(self) -> list:
        self.session.update_activity()
        return [k for k in self.vault.keys() if not k.startswith("_")]

    def search(self, query: str) -> list:
        self.session.update_activity()
        query = query.lower()
        return [k for k in self.vault.keys() if not k.startswith("_") and query in k.lower()]

    def generate_password(self, length: int = 16, use_special: bool = True) -> str:
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase), secrets.choice(string.digits)]
        if use_special:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        password += [secrets.choice(chars) for _ in range(length - len(password))]
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)


def copy_to_clipboard(text: str, clear_after: int = CLIPBOARD_TIMEOUT):
    try:
        import pyperclip
        pyperclip.copy(text)
        def clear_clipboard():
            time.sleep(clear_after)
            try:
                current = pyperclip.paste()
                if current == text:
                    pyperclip.copy("")
            except Exception:
                pass
        threading.Thread(target=clear_clipboard, daemon=True).start()
    except Exception:
        pass


# Adapter for legacy UI (keeps method names used in App)
class PasswordManagerAdapter:
    def __init__(self, core: PasswordManagerCore):
        self.core = core
        self.session = core.session
        self.vault = core.vault

    def is_initialized(self):
        return self.core.is_initialized()

    def initialize(self, password: str) -> tuple[bool, str]:
        # propagate both success flag and message from core so GUI can show errors
        ok, msg = self.core.initialize(password)
        return ok, msg

    def unlock(self, password: str) -> bool:
        return self.core.unlock(password)

    def lock(self):
        return self.core.lock()

    def add(self, name: str, username: str, password: str, notes: str = ""):
        return self.core.add_password(name, username, password, notes)

    def get(self, name: str):
        return self.core.get_password(name)

    def delete(self, name: str):
        return self.core.delete_password(name)

    def list_all(self):
        return self.core.list_services()

    def search(self, q: str):
        return self.core.search(q)

    def _save(self):
        # адаптируем вызов _save() из старого интерфейса
        if hasattr(self.core, '_save_vault'):
            return self.core._save_vault()
        if hasattr(self.core, '_save'):
            return self.core._save()

    def __getattr__(self, name):
        # предоставить совместимость для атрибутов, ожидаемых GUI
        if name == 'last_activity':
            return getattr(self.core, 'last_activity', getattr(self.core, 'session', None) and getattr(self.core.session, 'last_activity', None))
        # делегировать всё остальное к core
        return getattr(self.core, name)

    def generate(self, length=16, special=True):
        return self.core.generate_password(length, special)


class SettingsManager:
    def __init__(self):
        self.path = DATA_DIR / 'settings.json'
        self.defaults = {
            'pin_enabled': False,
            'auto_kill_suspicious': False,
            'suspicious_processes': ['ollydbg','x64dbg','ida','windbg','ghidra','dnspy','processhacker','procmon','wireshark','procdump','fiddler'],
            'clipboard_enabled': True
        }
        self._data = {}
        self._load()

    def _load(self):
        try:
            if self.path.exists():
                self._data = json.loads(self.path.read_text())
            else:
                self._data = self.defaults.copy()
                self._save()
        except Exception:
            self._data = self.defaults.copy()

    def _save(self):
        try:
            self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2))
            try:
                self.path.chmod(0o600)
            except Exception:
                pass
        except Exception:
            pass

    def get(self, key, default=None):
        return self._data.get(key, self.defaults.get(key, default))

    def set(self, key, value):
        self._data[key] = value
        self._save()

    def set_pin(self, pin: str) -> bool:
        try:
            ph = PasswordHasher()
            h = ph.hash(pin)
            PIN_FILE.write_text(h)
            try:
                PIN_FILE.chmod(0o600)
            except Exception:
                pass
            self.set('pin_enabled', True)
            return True
        except Exception:
            return False

    def clear_pin(self):
        try:
            if PIN_FILE.exists():
                PIN_FILE.unlink()
        except Exception:
            pass
        self.set('pin_enabled', False)

    def verify_pin(self, pin: str) -> bool:
        try:
            if not PIN_FILE.exists():
                return False
            stored = PIN_FILE.read_text().strip()
            ph = PasswordHasher()
            ph.verify(stored, pin)
            return True
        except Exception:
            return False


# create core instance for App to use
PasswordManagerCore = PasswordManagerCore

# --- end merge ---

def resource_path(relative_path):
    base = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base, relative_path)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DATA_DIR = Path.home() / ".password_manager"
DATA_FILE = DATA_DIR / "vault.enc"
SALT_FILE = DATA_DIR / "salt"
HMAC_KEY_FILE = DATA_DIR / "hmac"
BACKUP_DIR = DATA_DIR / "backups"
PIN_FILE = DATA_DIR / "pin.hash"
SESSION_TIMEOUT = 300  # 5 минут

COLORS = {
    'bg_dark': '#0a0a0f',
    'bg_card': '#1a1a24',
    'bg_hover': '#22222e',
    'accent': '#6366f1',
    'accent_hover': '#818cf8',
    'text': '#f1f1f3',
    'text_secondary': '#8b8b9e',
    'success': '#10b981',
    'error': '#ef4444',
    'border': '#2a2a38'
}


class PasswordManager:
    """Логика менеджера паролей"""
    
    def __init__(self):
        self.fernet = None
        self.vault = {}
        self.last_activity = time.time()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    def _get_salt(self) -> bytes:
        if SALT_FILE.exists():
            return SALT_FILE.read_bytes()
        salt = os.urandom(32)
        SALT_FILE.write_bytes(salt)
        return salt
    
    def _derive_key(self, password: str) -> bytes:
        salt = self._get_salt()
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
        return base64.urlsafe_b64encode(key)
    
    def is_initialized(self) -> bool:
        return DATA_FILE.exists()
    
    def initialize(self, password: str) -> bool:
        if self.is_initialized():
            return False
        key = self._derive_key(password)
        self.fernet = Fernet(key)
        self.vault = {"_created": datetime.now().isoformat()}
        self._save()
        return True
    
    def unlock(self, password: str) -> bool:
        key = self._derive_key(password)
        self.fernet = Fernet(key)
        try:
            data = self.fernet.decrypt(DATA_FILE.read_bytes())
            self.vault = json.loads(data.decode())
            self.last_activity = time.time()
            return True
        except InvalidToken:
            self.fernet = None
            return False
    
    def lock(self):
        self.fernet = None
        self.vault = {}
    
    def _save(self):
        data = json.dumps(self.vault, ensure_ascii=False)
        DATA_FILE.write_bytes(self.fernet.encrypt(data.encode()))
    
    def add(self, name: str, username: str, password: str, notes: str = ""):
        self.vault[name] = {
            'username': username,
            'password': password,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        self._save()
        self.last_activity = time.time()
    
    def get(self, name: str) -> dict:
        self.last_activity = time.time()
        return self.vault.get(name)
    
    def delete(self, name: str):
        if name in self.vault:
            del self.vault[name]
            self._save()
        self.last_activity = time.time()
    
    def list_all(self) -> list:
        self.last_activity = time.time()
        return [k for k in self.vault.keys() if k != "_created"]
    
    def search(self, query: str) -> list:
        query = query.lower()
        return [k for k in self.list_all() if query in k.lower()]
    
    @staticmethod
    def generate(length: int = 16, special: bool = True) -> str:
        chars = string.ascii_letters + string.digits
        if special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pwd = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        if special:
            pwd.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        pwd += [secrets.choice(chars) for _ in range(length - len(pwd))]
        secrets.SystemRandom().shuffle(pwd)
        return ''.join(pwd)


class AnimatedButton(ctk.CTkButton):
    """Кнопка с анимацией"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_color = kwargs.get('fg_color', COLORS['accent'])
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
    
    def _on_enter(self, e=None):
        self.configure(fg_color=COLORS['accent_hover'])
    
    def _on_leave(self, e=None):
        self.configure(fg_color=self.default_color)


class PasswordCard(ctk.CTkFrame):
    """Карточка пароля в списке"""
    
    def __init__(self, parent, name: str, username: str, on_click, **kwargs):
        super().__init__(parent, fg_color=COLORS['bg_card'], corner_radius=12, **kwargs)
        
        self.name = name
        self.on_click = on_click
        
        self.configure(cursor="hand2")
        self.bind('<Button-1>', self._clicked)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        
        icon_frame = ctk.CTkFrame(self, width=42, height=42, fg_color=COLORS['accent'], corner_radius=10)
        icon_frame.pack(side='left', padx=12, pady=12)
        icon_frame.pack_propagate(False)
        icon_frame.bind('<Button-1>', self._clicked)
        
        icon_label = ctk.CTkLabel(icon_frame, text=name[0].upper(), font=('Segoe UI', 16, 'bold'), text_color='white')
        icon_label.place(relx=0.5, rely=0.5, anchor='center')
        icon_label.bind('<Button-1>', self._clicked)
        
        info_frame = ctk.CTkFrame(self, fg_color='transparent')
        info_frame.pack(side='left', fill='both', expand=True, pady=12)
        info_frame.bind('<Button-1>', self._clicked)
        
        name_label = ctk.CTkLabel(info_frame, text=name, font=('Segoe UI', 14, 'bold'), 
                                   text_color=COLORS['text'], anchor='w')
        name_label.pack(fill='x')
        name_label.bind('<Button-1>', self._clicked)
        
        user_label = ctk.CTkLabel(info_frame, text=username or 'Нет логина', 
                                   font=('Segoe UI', 12), text_color=COLORS['text_secondary'], anchor='w')
        user_label.pack(fill='x')
        user_label.bind('<Button-1>', self._clicked)
        
        arrow = ctk.CTkLabel(self, text="→", font=('Segoe UI', 18), text_color=COLORS['text_secondary'])
        arrow.pack(side='right', padx=16)
        arrow.bind('<Button-1>', self._clicked)
    
    def _clicked(self, e):
        self.on_click(self.name)
    
    def _on_enter(self, e):
        self.configure(fg_color=COLORS['bg_hover'])
    
    def _on_leave(self, e):
        self.configure(fg_color=COLORS['bg_card'])


class Toast(ctk.CTkFrame):
    """Всплывающее уведомление"""
    
    def __init__(self, parent, message: str, toast_type: str = 'success'):
        super().__init__(parent, fg_color=COLORS['bg_card'], corner_radius=12)
        
        color = COLORS['success'] if toast_type == 'success' else COLORS['error']
        icon = "✓" if toast_type == 'success' else "✕"
        
        ctk.CTkLabel(self, text=icon, font=('Segoe UI', 14), text_color=color).pack(side='left', padx=(16, 8), pady=12)
        ctk.CTkLabel(self, text=message, font=('Segoe UI', 13), text_color=COLORS['text']).pack(side='left', padx=(0, 16), pady=12)
        
        self.place(relx=0.5, rely=0.95, anchor='center')
        self.after(2500, self._fade_out)
    
    def _fade_out(self):
        self.destroy()


class App(ctk.CTk):
    """Главное окно приложения"""
    
    def __init__(self):
        super().__init__()
        
        # Use adapter to provide legacy UI methods expected by GUI (list_all, add, etc.)
        self.pm = PasswordManagerAdapter(PasswordManagerCore())
        self.current_password = None
        
        self.title("Password Manager")
        self.geometry("420x680")
        self.minsize(380, 600)
        self.configure(fg_color=COLORS['bg_dark'])
        
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 420) // 2
        y = (self.winfo_screenheight() - 680) // 2
        self.geometry(f"+{x}+{y}")
        try:
            # Попробуем сначала корневую иконку, затем assets
            try:
                self.iconbitmap(resource_path('app.ico'))
            except Exception:
                self.iconbitmap(resource_path('assets/app.ico'))
        except Exception:
            pass
        
        self.container = ctk.CTkFrame(self, fg_color='transparent')
        self.container.pack(fill='both', expand=True, padx=20, pady=20)
        
        self.screens = {}
        self._create_auth_screen()
        self._create_main_screen()
        self._create_add_screen()
        self._create_view_screen()
        
        if self.pm.is_initialized():
            self._show_screen('auth')
        else:
            self._show_screen('auth')
            self.auth_title.configure(text="Создайте мастер-пароль")
            self.auth_confirm_frame.pack(fill='x', pady=(0, 16))
            self.auth_btn.configure(text="Создать хранилище")
            self.auth_btn.configure(state='disabled')
            self.auth_hint.configure(text="Минимум 8 символов. Запомните — восстановление невозможно.")
        
        self.auth_btn.pack(fill='x', pady=(8, 0))
        # Упаковать кнопку сброса под кнопкой авторизации/создания
        try:
            self.reset_vault_btn.pack(fill='x', pady=(8, 0))
        except Exception:
            pass
        
        self._start_session_timer()
    
    def _create_auth_screen(self):
        """Экран авторизации"""
        screen = ctk.CTkFrame(self.container, fg_color='transparent')
        self.screens['auth'] = screen
        
        logo_frame = ctk.CTkFrame(screen, width=64, height=64, fg_color=COLORS['accent'], corner_radius=16)
        logo_frame.pack(pady=(40, 16))
        logo_frame.pack_propagate(False)
        ctk.CTkLabel(logo_frame, text="🔐", font=('Segoe UI', 28)).place(relx=0.5, rely=0.5, anchor='center')
        
        ctk.CTkLabel(screen, text="Password Manager", font=('Segoe UI', 22, 'bold'), text_color=COLORS['text']).pack()
        ctk.CTkLabel(screen, text="Ваши пароли в безопасности", font=('Segoe UI', 13), text_color=COLORS['text_secondary']).pack(pady=(4, 30))
        
        card = ctk.CTkFrame(screen, fg_color=COLORS['bg_card'], corner_radius=16)
        card.pack(fill='x', pady=10)
        
        form = ctk.CTkFrame(card, fg_color='transparent')
        form.pack(fill='x', padx=24, pady=24)
        
        self.auth_title = ctk.CTkLabel(form, text="Мастер-пароль", font=('Segoe UI', 13), text_color=COLORS['text_secondary'], anchor='w')
        self.auth_title.pack(fill='x', pady=(0, 8))
        
        self.auth_password = ctk.CTkEntry(form, placeholder_text="Введите пароль", show="●", height=48, 
                                           font=('Segoe UI', 14), corner_radius=12)
        self.auth_password.pack(fill='x', pady=(0, 16))
        self.auth_password.bind('<Return>', lambda e: self._handle_auth())
        
        # Strength meter and show-password toggle
        self.auth_strength_bar = ctk.CTkProgressBar(form, mode='determinate')
        self.auth_strength_bar.set(0.0)
        self.auth_strength_bar.pack(fill='x', pady=(6,4))
        self.auth_strength_label = ctk.CTkLabel(form, text="", font=('Segoe UI', 11), text_color=COLORS['text_secondary'])
        self.auth_strength_label.pack(anchor='w')
        self.auth_show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(form, text='Показать пароль', variable=self.auth_show_var, command=self._toggle_auth_show).pack(anchor='w', pady=(6,6))

        self.auth_confirm_frame = ctk.CTkFrame(form, fg_color='transparent')
        ctk.CTkLabel(self.auth_confirm_frame, text="Подтвердите пароль", font=('Segoe UI', 13), 
                     text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 8))
        self.auth_confirm = ctk.CTkEntry(self.auth_confirm_frame, placeholder_text="Повторите пароль", 
                                          show="●", height=48, font=('Segoe UI', 14), corner_radius=12)
        self.auth_confirm.pack(fill='x')
        self.auth_confirm.bind('<Return>', lambda e: self._handle_auth())

        # dynamic strength update
        self.auth_password.bind('<KeyRelease>', lambda e: self._update_auth_strength())
        self.auth_confirm.bind('<KeyRelease>', lambda e: self._update_auth_strength())
        
        self.auth_btn = AnimatedButton(form, text="Разблокировать", height=48, font=('Segoe UI', 14, 'bold'),
                                        corner_radius=12, fg_color=COLORS['accent'], command=self._handle_auth)
        
        # Кнопка для сброса хранилища при утере мастер-пароля (упаковка делается в __init__ после кнопки авторизации)
        self.reset_vault_btn = ctk.CTkButton(form, text='Забыли пароль? Сбросить хранилище', height=40,
                            fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                            command=self._show_reset_auth_dialog)
        self.auth_hint = ctk.CTkLabel(screen, text="", font=('Segoe UI', 12), text_color=COLORS['text_secondary'], wraplength=350)
        self.auth_hint.pack(pady=16)
    
    def _create_main_screen(self):
        """Главный экран со списком паролей"""
        screen = ctk.CTkFrame(self.container, fg_color='transparent')
        self.screens['main'] = screen
        
        header = ctk.CTkFrame(screen, fg_color='transparent')
        header.pack(fill='x', pady=(0, 16))
        
        ctk.CTkLabel(header, text="Пароли", font=('Segoe UI', 24, 'bold'), text_color=COLORS['text']).pack(side='left')
        
        lock_btn = ctk.CTkButton(header, text="🔒", width=44, height=44, corner_radius=12,
                                  fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                  command=self._lock)
        lock_btn.pack(side='right')
        settings_btn = AnimatedButton(header, text="⚙", width=44, height=44, corner_radius=12,
                                      fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                      command=self.show_settings)
        settings_btn.pack(side='right', padx=(0,8))
        
        toolbar = ctk.CTkFrame(screen, fg_color='transparent')
        toolbar.pack(fill='x', pady=(0, 16))
        
        self.search_entry = ctk.CTkEntry(toolbar, placeholder_text="🔍  Поиск...", height=44,
                                          font=('Segoe UI', 13), corner_radius=12)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(0, 12))
        self.search_entry.bind('<KeyRelease>', lambda e: self._filter_passwords())
        
        add_btn = AnimatedButton(toolbar, text="+", width=44, height=44, corner_radius=12,
                                  font=('Segoe UI', 20), fg_color=COLORS['accent'], command=self._show_add)
        add_btn.pack(side='right')
        
        self.password_list = ctk.CTkScrollableFrame(screen, fg_color='transparent')
        self.password_list.pack(fill='both', expand=True)
    
    def _create_add_screen(self):
        """Экран добавления пароля"""
        screen = ctk.CTkFrame(self.container, fg_color='transparent')
        self.screens['add'] = screen
        

        header = ctk.CTkFrame(screen, fg_color='transparent')
        header.pack(fill='x', pady=(0, 20))
        
        back_btn = ctk.CTkButton(header, text="←", width=44, height=44, corner_radius=12,
                                  fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                  font=('Segoe UI', 18), command=lambda: self._show_screen('main'))
        back_btn.pack(side='left')
        
        ctk.CTkLabel(header, text="Новый пароль", font=('Segoe UI', 20, 'bold'), text_color=COLORS['text']).pack(side='left', padx=16)
        
        card = ctk.CTkScrollableFrame(screen, fg_color=COLORS['bg_card'], corner_radius=16)
        card.pack(fill='both', expand=True, pady=(0, 8))
        
        form = ctk.CTkFrame(card, fg_color='transparent')
        form.pack(fill='x', padx=24, pady=24)
        
        ctk.CTkLabel(form, text="Название сервиса", font=('Segoe UI', 13), text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 6))
        self.add_name = ctk.CTkEntry(form, placeholder_text="Google, GitHub...", height=44, font=('Segoe UI', 14), corner_radius=10)
        self.add_name.pack(fill='x', pady=(0, 16))
        
        ctk.CTkLabel(form, text="Логин / Email", font=('Segoe UI', 13), text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 6))
        self.add_username = ctk.CTkEntry(form, placeholder_text="user@example.com", height=44, font=('Segoe UI', 14), corner_radius=10)
        self.add_username.pack(fill='x', pady=(0, 16))
        
        ctk.CTkLabel(form, text="Пароль", font=('Segoe UI', 13), text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 6))
        
        pwd_frame = ctk.CTkFrame(form, fg_color='transparent')
        pwd_frame.pack(fill='x', pady=(0, 16))
        
        self.add_password = ctk.CTkEntry(pwd_frame, placeholder_text="Пароль", show="●", height=44, font=('Segoe UI', 14), corner_radius=10)
        self.add_password.pack(side='left', fill='x', expand=True, padx=(0, 8))
        
        self.add_show_var = False
        self.add_show_btn = ctk.CTkButton(pwd_frame, text="👁", width=44, height=44, corner_radius=10,
                                  fg_color='transparent', hover_color=COLORS['bg_hover'],
                                  command=self._toggle_add_password)
        self.add_show_btn.pack(side='right', padx=(0, 8))
        
        gen_btn = ctk.CTkButton(pwd_frame, text="🎲", width=44, height=44, corner_radius=10,
                                 fg_color=COLORS['bg_hover'], hover_color=COLORS['accent'],
                                 command=self._generate_password)
        gen_btn.pack(side='right')
        
        gen_frame = ctk.CTkFrame(form, fg_color=COLORS['bg_dark'], corner_radius=10)
        gen_frame.pack(fill='x', pady=(0, 16))
        
        gen_inner = ctk.CTkFrame(gen_frame, fg_color='transparent')
        gen_inner.pack(fill='x', padx=12, pady=12)
        
        self.length_label = ctk.CTkLabel(gen_inner, text="Длина: 16", font=('Segoe UI', 12), text_color=COLORS['text_secondary'])
        self.length_label.pack(anchor='w')
        
        self.length_slider = ctk.CTkSlider(gen_inner, from_=8, to=32, number_of_steps=24, 
                                            command=self._update_length)
        self.length_slider.set(16)
        self.length_slider.pack(fill='x', pady=8)
        
        self.special_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(gen_inner, text="Спецсимволы (!@#$)", variable=self.special_var,
                        font=('Segoe UI', 12), text_color=COLORS['text_secondary']).pack(anchor='w')
        
        ctk.CTkLabel(form, text="Заметки", font=('Segoe UI', 13), text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 6))
        self.add_notes = ctk.CTkTextbox(form, height=80, font=('Segoe UI', 13), corner_radius=10)
        self.add_notes.pack(fill='x', pady=(0, 16))
        
        footer = ctk.CTkFrame(screen, fg_color='transparent')
        footer.pack(side='bottom', fill='x', padx=24, pady=(12, 12))
        self.add_save_btn = AnimatedButton(footer, text="Сохранить", height=48, font=('Segoe UI', 14, 'bold'),
                       corner_radius=12, fg_color=COLORS['accent'], command=self._save_password)
        self.add_save_btn.pack(fill='x')
    
    def _create_view_screen(self):
        """Экран просмотра пароля"""
        screen = ctk.CTkFrame(self.container, fg_color='transparent')
        self.screens['view'] = screen
        
        header = ctk.CTkFrame(screen, fg_color='transparent')
        header.pack(fill='x', pady=(0, 20))
        
        back_btn = ctk.CTkButton(header, text="←", width=44, height=44, corner_radius=12,
                                  fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                  font=('Segoe UI', 18), command=lambda: self._show_screen('main'))
        back_btn.pack(side='left')
        
        self.view_title = ctk.CTkLabel(header, text="", font=('Segoe UI', 20, 'bold'), text_color=COLORS['text'])
        self.view_title.pack(side='left', padx=16)
        
        self.view_edit_btn = ctk.CTkButton(header, text="Изменить", width=80, height=36, corner_radius=10,
                                 fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                 command=self._enter_edit_mode)
        self.view_edit_btn.pack(side='right')
        
        self.edit_name = ctk.CTkEntry(header, placeholder_text="Название", font=('Segoe UI', 18, 'bold'))
        
        card = ctk.CTkFrame(screen, fg_color=COLORS['bg_card'], corner_radius=16)
        card.pack(fill='x')
        
        content = ctk.CTkFrame(card, fg_color='transparent')
        content.pack(fill='x', padx=24, pady=24)
        
        ctk.CTkLabel(content, text="ЛОГИН", font=('Segoe UI', 11), text_color=COLORS['text_secondary']).pack(anchor='w')
        self.view_username = ctk.CTkLabel(content, text="", font=('Segoe UI', 15), text_color=COLORS['text'], anchor='w')
        self.view_username.pack(fill='x', pady=(4, 16))
        self.edit_username = ctk.CTkEntry(content, font=('Segoe UI', 15))
        
        ctk.CTkLabel(content, text="ПАРОЛЬ", font=('Segoe UI', 11), text_color=COLORS['text_secondary']).pack(anchor='w')
        
        pwd_frame = ctk.CTkFrame(content, fg_color=COLORS['bg_dark'], corner_radius=10)
        pwd_frame.pack(fill='x', pady=(4, 16))
        
        pwd_inner = ctk.CTkFrame(pwd_frame, fg_color='transparent')
        pwd_inner.pack(fill='x', padx=12, pady=10)
        
        self.view_password = ctk.CTkLabel(pwd_inner, text="••••••••••••", font=('Consolas', 14), 
                                           text_color=COLORS['text'], anchor='w')
        self.view_password.pack(side='left', fill='x', expand=True)
        
        self.show_pwd_var = False
        
        self.view_show_btn = ctk.CTkButton(pwd_inner, text="👁", width=36, height=36, corner_radius=8,
                                  fg_color='transparent', hover_color=COLORS['bg_hover'],
                                  command=self._toggle_password)
        self.view_show_btn.pack(side='right', padx=(8, 0))
        
        self.view_copy_btn = ctk.CTkButton(pwd_inner, text="📋", width=36, height=36, corner_radius=8,
                                  fg_color='transparent', hover_color=COLORS['bg_hover'],
                                  command=self._copy_password)
        self.view_copy_btn.pack(side='right')
        
        self.edit_password = ctk.CTkEntry(pwd_inner, show="●", font=('Consolas', 14))
        
        self.view_notes_frame = ctk.CTkFrame(content, fg_color='transparent')
        ctk.CTkLabel(self.view_notes_frame, text="ЗАМЕТКИ", font=('Segoe UI', 11), text_color=COLORS['text_secondary']).pack(anchor='w')
        self.view_notes = ctk.CTkLabel(self.view_notes_frame, text="", font=('Segoe UI', 13), 
                                        text_color=COLORS['text'], anchor='w', wraplength=320, justify='left')
        self.view_notes.pack(fill='x', pady=(4, 0))
        
        self.edit_notes = ctk.CTkTextbox(content, height=80, font=('Segoe UI', 13), corner_radius=10)
        
        self.edit_actions = ctk.CTkFrame(content, fg_color='transparent')
        self.edit_save_btn = AnimatedButton(self.edit_actions, text="Сохранить", height=44, font=('Segoe UI', 14, 'bold'),
                                           corner_radius=10, fg_color=COLORS['accent'], command=self._save_edit)
        self.edit_save_btn.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.edit_cancel_btn = ctk.CTkButton(self.edit_actions, text="Отмена", height=44, font=('Segoe UI', 14),
                                            corner_radius=10, fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                            command=self._cancel_edit)
        self.edit_cancel_btn.pack(side='right')
        
        self.view_delete_btn = ctk.CTkButton(content, text="Удалить", height=44, font=('Segoe UI', 14),
                                    corner_radius=10, fg_color='#2d1f1f', hover_color='#3d2525',
                                    text_color=COLORS['error'], command=self._delete_password)
        self.view_delete_btn.pack(fill='x', pady=(16, 0))
    
    def _show_screen(self, name: str):
        """Показать экран"""
        for screen in self.screens.values():
            screen.pack_forget()
        self.screens[name].pack(fill='both', expand=True)
        
        if name == 'main':
            self._load_passwords()
    
    def _handle_auth(self):
        """Обработка авторизации"""
        password = self.auth_password.get()
        creating = self.auth_confirm_frame.winfo_ismapped()
        
        # Если файл существует и мы не находимся в режиме создания (подтверждение видно), то пытаемся разблокировать
        if self.pm.is_initialized() and not creating:
            if self.pm.unlock(password):
                self._show_toast("Хранилище разблокировано", "success")
                self._show_screen('main')
                self.auth_password.delete(0, 'end')
            else:
                self._show_toast("Неверный пароль", "error")
            return
        
        # Режим создания (либо хранилище не создано, либо пользователь явно в режиме создания)
        confirm = self.auth_confirm.get()
        # stronger validation using SecurityUtils
        valid, msg = SecurityUtils.validate_password_strength(password)
        if not valid:
            self._show_toast(msg or "Слабый пароль", "error")
            return
        if password != confirm:
            self._show_toast("Пароли не совпадают", "error")
            return
        ok, msg = self.pm.initialize(password)
        if not ok:
            # показать подробную причину неудачи, если имеется
            self._show_toast(msg or "Не удалось создать хранилище", "error")
            return
        # сразу разблокируем после создания
        self.pm.unlock(password)
        self._show_toast("Хранилище создано", "success")
        self._show_screen('main')
        self.auth_password.delete(0, 'end')
        self.auth_confirm.delete(0, 'end')

    def _show_reset_auth_dialog(self):
        """Показать диалог подтверждения удаления всех данных из авторизационного экрана"""
        dlg = ctk.CTkToplevel(self)
        dlg.title('Сброс хранилища')
        dlg.geometry('480x260')
        dlg.configure(fg_color=COLORS['bg_dark'])

        frame = ctk.CTkFrame(dlg, fg_color=COLORS['bg_dark'])
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        ctk.CTkLabel(frame, text='Внимание', font=('Segoe UI', 16, 'bold'), text_color=COLORS['error']).pack(anchor='w')
        ctk.CTkLabel(frame, text='Если вы не помните мастер-пароль — все данные будут удалены безвозвратно.\n'
                     'После удаления вы создадите новый мастер-пароль и новое пустое хранилище.',
                     wraplength=440, text_color=COLORS['text_secondary']).pack(anchor='w', pady=(8,12))

        confirm_var = ctk.BooleanVar(value=False)
        chk = ctk.CTkCheckBox(frame, text='Я понимаю, что все данные будут удалены навсегда', variable=confirm_var)
        chk.pack(anchor='w', pady=(0,12))

        btn_frame = ctk.CTkFrame(frame, fg_color='transparent')
        btn_frame.pack(fill='x', pady=(8,0))

        cancel_btn = ctk.CTkButton(btn_frame, text='Отмена', fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                                   command=dlg.destroy)
        cancel_btn.pack(side='right', padx=(8,0))

        delete_btn = ctk.CTkButton(btn_frame, text='Удалить всё', fg_color=COLORS['error'], hover_color=COLORS['error'],
                                   command=lambda: [self._perform_reset_vault(), dlg.destroy()])
        delete_btn.pack(side='right')

        # изначально запретить кнопку удаления
        delete_btn.configure(state='disabled')

        def on_chk():
            delete_btn.configure(state='normal' if confirm_var.get() else 'disabled')

        confirm_var.trace_add('write', lambda *a: on_chk())

    def _perform_reset_vault(self):
        """Удалить файлы хранилища, резервов и настройки, очистить PIN и переключиться в режим создания"""
        try:
            settings_path = DATA_DIR / 'settings.json'
            paths = [DATA_FILE, SALT_FILE, HMAC_KEY_FILE, PIN_FILE, settings_path]
            problems = []
            for p in paths:
                try:
                    if p and p.exists():
                        if p.is_file():
                            p.unlink()
                        elif p.is_dir():
                            for f in p.glob('*'):
                                try:
                                    if f.is_file():
                                        f.unlink()
                                except Exception:
                                    pass
                except Exception as ex:
                    problems.append((p, ex))
            # удалить резервные копии
            try:
                if BACKUP_DIR.exists():
                    for b in BACKUP_DIR.glob('vault_*.enc'):
                        try:
                            b.unlink()
                        except Exception:
                            pass
            except Exception:
                pass

            # очистить PIN и память
            try:
                SettingsManager().clear_pin()
            except Exception:
                pass

            # ensure data dir exists so next initialization can create files reliably
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

            # recreate core instance to clear any previous cached state
            try:
                self.pm = PasswordManagerAdapter(PasswordManagerCore())
            except Exception:
                pass

            # переключиться на экран создания мастер-пароля
            self.auth_title.configure(text='Создайте мастер-пароль')
            # Убрать кнопку и упаковать поля в нужном порядке (подтверждение должно быть выше кнопки)
            try:
                self.auth_btn.pack_forget()
            except Exception:
                pass
            self.auth_confirm_frame.pack(fill='x', pady=(0, 16))
            self.auth_btn.configure(text='Создать хранилище')
            self.auth_btn.configure(state='disabled')
            self.auth_hint.configure(text='Минимум 8 символов. Запомните — восстановление невозможно.')
            # Очистить поля на случай старых значений
            try:
                self.auth_password.delete(0, 'end')
                self.auth_confirm.delete(0, 'end')
            except Exception:
                pass
            # Показать экран и восстановить порядок кнопок
            self._show_screen('auth')
            try:
                self.auth_btn.pack(fill='x', pady=(8, 0))
                self.reset_vault_btn.pack(fill='x', pady=(8, 0))
            except Exception:
                pass

            if problems:
                # записать подробный лог проблем удаления в файл для диагностики
                try:
                    log_path = DATA_DIR / 'reset.log'
                    with log_path.open('a', encoding='utf-8') as f:
                        f.write(f"{datetime.now().isoformat()} Reset problems:\n")
                        for p, ex in problems:
                            f.write(f"- {p}: {ex}\n")
                        f.write("\n")
                except Exception:
                    pass
                # показать предупреждение, если какие-то файлы не удалось удалить
                self._show_toast('Некоторые файлы не удалось удалить полностью (см. reset.log)', 'error')
                for p, ex in problems:
                    print(f'Failed to remove {p}: {ex}')
            else:
                self._show_toast('Хранилище удалено', 'success')
        except Exception as e:
            messagebox.showerror('Ошибка', f'Не удалось удалить хранилище: {e}')

    def _toggle_auth_show(self):
        try:
            show = self.auth_show_var.get()
            self.auth_password.configure(show="" if show else "●")
            self.auth_confirm.configure(show="" if show else "●")
        except Exception:
            pass

    def _update_auth_strength(self):
        pwd = self.auth_password.get() or ''
        score = 0
        msg = ''
        if zxcvbn is not None and pwd:
            try:
                res = zxcvbn(pwd)
                score = res.get('score', 0)
                warn = res.get('feedback', {}).get('warning','') or ''
                msg = f"Оценка: {score}/4. {warn}"
            except Exception:
                pass
        else:
            # heuristic
            score = 0
            if len(pwd) >= MIN_PASSWORD_LENGTH:
                score += 2
            if any(c.isupper() for c in pwd):
                score += 1
            if any(c.isdigit() for c in pwd):
                score += 1
            if any(not c.isalnum() for c in pwd):
                score += 1
            if score > 4:
                score = 4
            msg = 'OK' if score >= 3 else ('Слабый пароль' if pwd else '')
        # update UI
        self.auth_strength_bar.set((score + 1)/5 if pwd else 0.0)
        try:
            self.auth_strength_label.configure(text=msg)
        except Exception:
            pass
        # enable/disable create button when in creation mode
        creating = self.auth_confirm_frame.winfo_ismapped()
        if creating:
            enabled = False
            if pwd and (self.auth_confirm.get() == pwd):
                # require score >=3
                if score >= 3:
                    enabled = True
            self.auth_btn.configure(state='normal' if enabled else 'disabled')
    
    def _lock(self):
        """Заблокировать хранилище"""
        self.pm.lock()
        self.auth_title.configure(text="Мастер-пароль")
        self.auth_confirm_frame.pack_forget()
        self.auth_btn.configure(text="Разблокировать")
        self.auth_hint.configure(text="")
        self._show_screen('auth')
        self._show_toast("Хранилище заблокировано", "success")
    
    def _load_passwords(self):
        """Загрузить список паролей"""
        for widget in self.password_list.winfo_children():
            widget.destroy()
        
        passwords = self.pm.list_all()
        query = self.search_entry.get().lower()
        
        if query:
            passwords = [p for p in passwords if query in p.lower()]
        
        if not passwords:
            empty = ctk.CTkFrame(self.password_list, fg_color='transparent')
            empty.pack(fill='both', expand=True, pady=60)
            ctk.CTkLabel(empty, text="🔑", font=('Segoe UI', 48)).pack()
            ctk.CTkLabel(empty, text="Нет паролей" if not self.pm.list_all() else "Ничего не найдено",
                         font=('Segoe UI', 16, 'bold'), text_color=COLORS['text']).pack(pady=(16, 4))
            ctk.CTkLabel(empty, text="Нажмите + чтобы добавить" if not self.pm.list_all() else "",
                         font=('Segoe UI', 13), text_color=COLORS['text_secondary']).pack()
            return
        
        for name in sorted(passwords):
            data = self.pm.get(name)
            card = PasswordCard(self.password_list, name, data.get('username', ''), self._show_view)
            card.pack(fill='x', pady=(0, 8))
    
    def _filter_passwords(self):
        """Фильтрация паролей"""
        self._load_passwords()
    
    def _show_add(self):
        """Показать экран добавления"""
        self.add_name.delete(0, 'end')
        self.add_username.delete(0, 'end')
        self.add_password.delete(0, 'end')
        self.add_notes.delete('1.0', 'end')
        self._generate_password()
        self._show_screen('add')
    
    def _update_length(self, value):
        """Обновить длину пароля"""
        self.length_label.configure(text=f"Длина: {int(value)}")
    
    def _generate_password(self):
        """Сгенерировать пароль"""
        length = int(self.length_slider.get())
        special = self.special_var.get()
        pwd = PasswordManager.generate(length, special)
        self.add_password.delete(0, 'end')
        self.add_password.insert(0, pwd)
        if getattr(self, 'add_show_var', False):
            self.add_password.configure(show="")
        else:
            self.add_password.configure(show="")
            self.after(3000, lambda: self.add_password.configure(show="●"))
    
    def _save_password(self):
        """Сохранить пароль"""
        name = self.add_name.get().strip()
        username = self.add_username.get().strip()
        password = self.add_password.get()
        notes = self.add_notes.get('1.0', 'end').strip()
        
        if not name:
            self._show_toast("Введите название", "error")
            return
        
        if not password:
            self._show_toast("Введите пароль", "error")
            return
        
        try:
            self.pm.add(name, username, password, notes)
        except Exception as e:
            # show helpful error instead of crashing
            self._show_toast(str(e) or "Не удалось сохранить пароль", "error")
            return
        self._show_toast("Пароль сохранён", "success")
        self._show_screen('main')
    
    def _show_view(self, name: str):
        """Показать детали пароля"""
        self.current_password = name
        data = self.pm.get(name)
        
        self.in_edit_mode = False
        try:
            self.edit_name.pack_forget()
            self.edit_username.pack_forget()
            self.edit_password.pack_forget()
            self.edit_notes.pack_forget()
            self.edit_actions.pack_forget()
        except Exception:
            pass
        self.view_title.configure(text=name)
        self.view_title.pack(side='left', padx=16)
        self.view_edit_btn.configure(state='normal')
        self.view_username.configure(text=data.get('username') or '—')
        self.view_username.pack(fill='x', pady=(4, 16))
        self.view_password.configure(text="••••••••••••")
        self.show_pwd_var = False
        try:
            self.view_show_btn.configure(text='👁', command=self._toggle_password)
            self.view_copy_btn.configure(command=self._copy_password)
        except Exception:
            pass
        if data.get('notes'):
            self.view_notes.configure(text=data['notes'])
            self.view_notes_frame.pack(fill='x', pady=(0, 0))
        else:
            self.view_notes_frame.pack_forget()
        try:
            self.view_delete_btn.pack(fill='x', pady=(16, 0))
        except Exception:
            pass
        self._show_screen('view')
    
    def _toggle_password(self):
        """Показать/скрыть пароль (работает в режиме просмотра и в режиме редактирования)"""
        if getattr(self, 'in_edit_mode', False):
            self.edit_show_var = not getattr(self, 'edit_show_var', False)
            try:
                self.edit_password.configure(show="" if self.edit_show_var else "●")
                self.view_show_btn.configure(text="🙈" if self.edit_show_var else "👁")
            except Exception:
                pass
        else:
            data = self.pm.get(self.current_password)
            settings = SettingsManager()
            # Если пароль уже показан — скрыть
            if getattr(self, 'show_pwd_var', False):
                self.show_pwd_var = False
                self.view_password.configure(text="••••••••••••")
                try:
                    self.view_show_btn.configure(text="👁")
                except Exception:
                    pass
                return

            # Нужно показать — проверить PIN при необходимости
            if settings.get('pin_enabled'):
                pin = simpledialog.askstring('PIN', 'Введите PIN для просмотра записи:', show='*', parent=self)
                if not pin:
                    self._show_toast('PIN не введён', 'error')
                    return
                if not settings.verify_pin(pin):
                    self._show_toast('Неверный PIN', 'error')
                    return
                # опция авто-завершения
                if settings.get('auto_kill_suspicious') and psutil is not None:
                    self._scan_and_kill_suspicious(settings)

            # Показать пароль
            self.show_pwd_var = True
            self.view_password.configure(text=data['password'])
            try:
                self.view_show_btn.configure(text="🙈")
            except Exception:
                pass

    def _scan_and_kill_suspicious(self, settings: SettingsManager):
        """Поиск и завершение подозрительных процессов по списку имён"""
        suspects = [s.lower() for s in settings.get('suspicious_processes')]
        if not suspects:
            return
        if psutil is None:
            self._show_toast('psutil не установлен — скан недоступен', 'error')
            return
        killed = 0
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    if not name:
                        continue
                    for s in suspects:
                        if s in name:
                            try:
                                proc.terminate()
                                proc.wait(timeout=2)
                            except Exception:
                                try:
                                    proc.kill()
                                except Exception:
                                    pass
                            killed += 1
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        if killed:
            self._show_toast(f'Завершено {killed} подозрительных процессов', 'success')
        else:
            self._show_toast('Подозрительных процессов не найдено', 'success')
    
    def _toggle_add_password(self):
        """Переключить видимость пароля на экране добавления"""
        self.add_show_var = not getattr(self, 'add_show_var', False)
        try:
            self.add_password.configure(show="" if self.add_show_var else "●")
            self.add_show_btn.configure(text="🙈" if self.add_show_var else "👁")
        except Exception:
            pass
    
    def _copy_password(self):
        """Копировать пароль"""
        settings = SettingsManager()
        if not settings.get('clipboard_enabled'):
            self._show_toast('Копирование в буфер отключено в настройках', 'error')
            return
        # PIN check if enabled
        if settings.get('pin_enabled'):
            pin = simpledialog.askstring('PIN', 'Введите PIN для копирования:', show='*', parent=self)
            if not pin:
                self._show_toast('PIN не введён', 'error')
                return
            if not settings.verify_pin(pin):
                self._show_toast('Неверный PIN', 'error')
                return
            if settings.get('auto_kill_suspicious') and psutil is not None:
                self._scan_and_kill_suspicious(settings)

        data = self.pm.get(self.current_password)
        self.clipboard_clear()
        self.clipboard_append(data['password'])
        self._show_toast("Пароль скопирован", "success")
        
        def clear():
            time.sleep(30)
            try:
                self.clipboard_clear()
            except:
                pass
        threading.Thread(target=clear, daemon=True).start()
    
    def _delete_password(self):
        """Удалить пароль"""
        if messagebox.askyesno("Удаление", f"Удалить пароль для '{self.current_password}'?"):
            self.pm.delete(self.current_password)
            self._show_toast("Пароль удалён", "success")
            self._show_screen('main')
    
    def _enter_edit_mode(self):
        """Переключиться в режим редактирования"""
        if not self.current_password:
            return
        data = self.pm.get(self.current_password)
        self.in_edit_mode = True
        try:
            self.view_title.pack_forget()
            self.edit_name.delete(0, 'end')
            self.edit_name.insert(0, self.current_password)
            self.edit_name.pack(side='left', padx=16)
            self.view_edit_btn.configure(state='disabled')
        except Exception:
            pass
        try:
            self.view_username.pack_forget()
            self.edit_username.delete(0, 'end')
            self.edit_username.insert(0, data.get('username', ''))
            self.edit_username.pack(fill='x', pady=(4, 16))
        except Exception:
            pass
        try:
            self.view_password.pack_forget()
            self.edit_password.delete(0, 'end')
            self.edit_password.insert(0, data.get('password', ''))
            self.edit_password.pack(side='left', fill='x', expand=True)
            self.view_show_btn.configure(command=self._toggle_password)
            def copy_edit():
                self.clipboard_clear()
                self.clipboard_append(self.edit_password.get())
                self._show_toast("Пароль скопирован", "success")
            self.view_copy_btn.configure(command=copy_edit)
        except Exception:
            pass
        try:
            self.view_notes_frame.pack_forget()
            self.edit_notes.delete('1.0', 'end')
            self.edit_notes.insert('1.0', data.get('notes', ''))
            self.edit_notes.pack(fill='x', pady=(0, 0))
        except Exception:
            pass
        try:
            self.view_delete_btn.pack_forget()
            self.edit_actions.pack(fill='x', pady=(16, 0))
        except Exception:
            pass
    
    def _save_edit(self):
        """Сохранить изменения в записи"""
        new_name = self.edit_name.get().strip()
        if not new_name:
            self._show_toast("Введите название", "error")
            return
        if new_name != self.current_password and new_name in self.pm.vault:
            self._show_toast("Запись с таким именем уже существует", "error")
            return
        new_username = self.edit_username.get().strip()
        new_password = self.edit_password.get()
        new_notes = self.edit_notes.get('1.0', 'end').strip()
        old = self.pm.get(self.current_password) or {}
        created = old.get('created', datetime.now().isoformat())
        self.pm.vault[new_name] = {
            'username': new_username,
            'password': new_password,
            'notes': new_notes,
            'created': created,
            'modified': datetime.now().isoformat()
        }
        if new_name != self.current_password:
            try:
                del self.pm.vault[self.current_password]
            except KeyError:
                pass
        self.pm._save()
        self._show_toast("Изменения сохранены", "success")
        self._load_passwords()
        self._show_view(new_name)
    
    def _cancel_edit(self):
        """Отмена редактирования — восстановить вид"""
        self.in_edit_mode = False
        try:
            self.edit_actions.pack_forget()
            self.edit_name.pack_forget()
            self.edit_username.pack_forget()
            self.edit_password.pack_forget()
            self.edit_notes.pack_forget()
            self.view_show_btn.configure(command=self._toggle_password, text='👁')
            self.view_copy_btn.configure(command=self._copy_password)
            self.view_title.pack(side='left', padx=16)
            self.view_username.pack(fill='x', pady=(4, 16))
            self.view_password.pack(side='left', fill='x', expand=True)
            if self.pm.get(self.current_password).get('notes'):
                self.view_notes_frame.pack(fill='x', pady=(0, 0))
            else:
                self.view_notes_frame.pack_forget()
            self.view_delete_btn.pack(fill='x', pady=(16, 0))
            self.view_edit_btn.configure(state='normal')
        except Exception:
            pass
    
    def _toggle_edit_password(self):
        """Переключить видимость поля пароля в режиме редактирования (альтернатива)"""
        self.edit_show_var = not getattr(self, 'edit_show_var', False)
        try:
            self.edit_password.configure(show="" if self.edit_show_var else "●")
            self.view_show_btn.configure(text="🙈" if self.edit_show_var else "👁")
        except Exception:
            pass

    def _show_toast(self, message: str, toast_type: str = 'success'):
        """Показать уведомление"""
        Toast(self, message, toast_type)

    def show_settings(self):
        """Окно настроек: PIN, авто-завершение процессов, список процессов, clipboard"""
        self.pm.session.update_activity()
        settings = SettingsManager()

        dlg = ctk.CTkToplevel(self)
        dlg.title("Настройки")
        dlg.geometry("480x520")
        dlg.configure(fg_color=COLORS['bg_dark'])

        frame = ctk.CTkFrame(dlg, fg_color=COLORS['bg_dark'])
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # PIN
        pin_var = ctk.BooleanVar(value=settings.get('pin_enabled'))
        def on_pin_toggle():
            if pin_var.get():
                pd = ctk.CTkToplevel(dlg)
                pd.title('Установить PIN')
                pd.geometry('360x200')
                pd.configure(fg_color=COLORS['bg_dark'])
                ctk.CTkLabel(pd, text='Введите PIN (4-8 цифр):', text_color=COLORS['text']).pack(pady=(12,4))
                pin_entry = ctk.CTkEntry(pd, show='•')
                pin_entry.pack(fill='x', padx=12)
                ctk.CTkLabel(pd, text='Повторите PIN:', text_color=COLORS['text']).pack(pady=(12,4))
                pin_entry2 = ctk.CTkEntry(pd, show='•')
                pin_entry2.pack(fill='x', padx=12)
                def save_pin():
                    p1 = pin_entry.get().strip()
                    p2 = pin_entry2.get().strip()
                    if not p1 or p1 != p2:
                        messagebox.showerror('Ошибка', 'Пины не совпадают или пустые')
                        return
                    if not p1.isdigit() or not (4 <= len(p1) <= 8):
                        messagebox.showerror('Ошибка', 'PIN должен состоять из 4-8 цифр')
                        return
                    ok = settings.set_pin(p1)
                    if not ok:
                        messagebox.showerror('Ошибка', 'Не удалось сохранить PIN')
                    else:
                        messagebox.showinfo('Успех', 'PIN установлен')
                        pd.destroy()
                        dlg.focus_force()
                ctk.CTkButton(pd, text='Сохранить', command=save_pin, fg_color=COLORS['accent']).pack(fill='x', padx=12, pady=(12,0))
                return
            else:
                if messagebox.askyesno('Подтвердите', 'Отключить PIN?'):
                    settings.clear_pin()
                    pin_var.set(False)

        ctk.CTkCheckBox(frame, text='Включить PIN для просмотра записей', variable=pin_var, command=on_pin_toggle).pack(anchor='w', pady=(0,8))
        ctk.CTkLabel(frame, text='При попытке посмотреть пароль, потребуется ввод PIN. Во время ввода будет проверяться система на подозрительные процессы и при включённой опции они будут останавливаться.', wraplength=420, text_color=COLORS['text_secondary']).pack(anchor='w', pady=(0,12))

        # Auto-kill
        auto_kill_var = ctk.BooleanVar(value=settings.get('auto_kill_suspicious'))
        ctk.CTkCheckBox(frame, text='Автоматически завершать подозрительные процессы при вводе PIN', variable=auto_kill_var).pack(anchor='w', pady=(0,8))

        # Processes list
        ctk.CTkLabel(frame, text='Список подозрительных процессов (по имени):', text_color=COLORS['text']).pack(anchor='w', pady=(12,4))
        proc_txt = ctk.CTkTextbox(frame, height=120, fg_color=COLORS['bg_card'], text_color=COLORS['text'])
        proc_txt.pack(fill='x')
        proc_txt.insert('1.0', '\n'.join(settings.get('suspicious_processes')))

        # Clipboard
        clr_var = ctk.BooleanVar(value=settings.get('clipboard_enabled'))
        ctk.CTkCheckBox(frame, text='Разрешить использование буфера обмена', variable=clr_var).pack(anchor='w', pady=(12,8))

        def save_all():
            settings.set('pin_enabled', pin_var.get())
            settings.set('auto_kill_suspicious', auto_kill_var.get())
            settings.set('suspicious_processes', [s.strip() for s in proc_txt.get('1.0','end').splitlines() if s.strip()])
            settings.set('clipboard_enabled', clr_var.get())
            messagebox.showinfo('Успех', 'Настройки сохранены')
            dlg.destroy()

        ctk.CTkButton(frame, text='Сохранить', fg_color=COLORS['accent'], command=save_all).pack(fill='x', pady=(12,0))

        def reset_vault():
            if not messagebox.askyesno('Сброс хранилища', 'Вы уверены? Все пароли и связанные данные будут удалены безвозвратно.'):
                return
            try:
                # удалить основные файлы
                for p in [DATA_FILE, SALT_FILE, HMAC_KEY_FILE, PIN_FILE, SETTINGS_PATH if (SETTINGS_PATH := (DATA_DIR / 'settings.json')) else None]:
                    try:
                        if p and p.exists():
                            if p.is_file():
                                p.unlink()
                            elif p.is_dir():
                                for f in p.glob('*'):
                                    try:
                                        if f.is_file():
                                            f.unlink()
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                # удалить резервные копии
                try:
                    if BACKUP_DIR.exists():
                        for b in BACKUP_DIR.glob('vault_*.enc'):
                            try:
                                b.unlink()
                            except Exception:
                                pass
                except Exception:
                    pass
                # очистить память и заблокировать
                try:
                    settings.clear_pin()
                except Exception:
                    pass
                try:
                    self.pm.lock()
                except Exception:
                    pass
                messagebox.showinfo('Готово', 'Хранилище удалено. Перезапустите приложение или создайте новый мастер‑пароль.')
                # переключиться на экран авторизации в режиме создания
                self.auth_title.configure(text='Создайте мастер-пароль')
                self.auth_confirm_frame.pack(fill='x', pady=(0, 16))
                self.auth_btn.configure(text='Создать хранилище')
                self.auth_hint.configure(text='Минимум 8 символов. Запомните — восстановление невозможно.')
                self._show_screen('auth')
                dlg.destroy()
            except Exception as e:
                messagebox.showerror('Ошибка', f'Не удалось удалить хранилище: {e}')

        ctk.CTkButton(frame, text='Сбросить хранилище', fg_color=COLORS['error'], command=reset_vault).pack(fill='x', pady=(12,0))

    def _start_session_timer(self):
        def check():
            while True:
                time.sleep(30)
                if self.pm.fernet and time.time() - self.pm.last_activity > SESSION_TIMEOUT:
                    self.after(0, self._lock)
                    break

        threading.Thread(target=check, daemon=True).start()


if __name__ == "__main__":
    app = App()
    app.mainloop()
