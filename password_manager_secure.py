

import os
import sys
import json
import base64
import hashlib
import getpass
import secrets
import string
import time
import threading
import hmac
import shutil
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError


DATA_DIR = Path.home() / ".password_manager"
DATA_FILE = DATA_DIR / "vault.enc"
SALT_FILE = DATA_DIR / "salt"
HMAC_KEY_FILE = DATA_DIR / "hmac"
BACKUP_DIR = DATA_DIR / "backups"

SESSION_TIMEOUT = 120
CLIPBOARD_TIMEOUT = 10
PASSWORD_SHOW_TIMEOUT = 5
LOGIN_ATTEMPTS = 3
LOGIN_ATTEMPT_BACKOFF = [1, 2, 4]
MIN_PASSWORD_LENGTH = 10
VAULT_FORMAT_VERSION = 2


class SecurityUtils:
    
    @staticmethod
    def wipe_variable(var: str, length: int = 100):
        try:
            import ctypes
            ctypes.memmove(id(var), b'\x00' * length, length)
        except:
            pass
    
    @staticmethod
    def is_debugger_present() -> bool:
        return sys.gettrace() is not None
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
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
            HMAC_KEY_FILE.chmod(0o600)
    
    def _get_salt(self) -> bytes:
        if SALT_FILE.exists():
            return SALT_FILE.read_bytes()
        salt = os.urandom(32)
        SALT_FILE.write_bytes(salt)
        SALT_FILE.chmod(0o600)
        return salt
    
    def _get_hmac_key(self) -> bytes:
        return HMAC_KEY_FILE.read_bytes()
    
    def derive_key_argon2(self, master_password: str) -> bytes:
        salt = self._get_salt()
        
        try:
            hash_obj = self.ph.hash(master_password)
            hash_bytes = hashlib.sha256(hash_obj.encode()).digest()
            
            key = hashlib.pbkdf2_hmac(
                'sha256',
                hash_bytes,
                salt,
                iterations=100,
                dklen=32
            )
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
        except:
            return False


class SessionManager:
    
    def __init__(self, timeout: int = SESSION_TIMEOUT):
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


class PasswordManager:
    
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
            print("⚠️ AVERTISSEMENT: Debugger détecté!")
    
    def is_initialized(self) -> bool:
        return DATA_FILE.exists()
    
    def initialize(self, master_password: str) -> bool:
        if self.is_initialized():
            return False
        
        valid, msg = SecurityUtils.validate_password_strength(master_password)
        if not valid:
            print(f"❌ {msg}")
            return False
        
        try:
            self.master_hash = self.crypto.ph.hash(master_password)
            
            key = self.crypto.derive_key_argon2(master_password)
            self.fernet = Fernet(key)
            
            self.vault = {
                "_format_version": VAULT_FORMAT_VERSION,
                "_created": datetime.now().isoformat(),
                "_master_hash": self.master_hash
            }
            
            self._save_vault()
            print("✓ Хранилище успешно создано!")
            return True
        except Exception as e:
            print(f"❌ Ошибка при создании: {e}")
            return False
    
    def unlock(self, master_password: str) -> bool:
        if self._login_attempts >= LOGIN_ATTEMPTS:
            print(f"❌ Trop de tentatives. Attendre 30 secondes...")
            return False
        
        try:
            encrypted_data = DATA_FILE.read_bytes()
            self._verify_vault_integrity(encrypted_data)
            
            vault_preview = json.loads(self.fernet.decrypt(encrypted_data).decode())
            stored_hash = vault_preview.get("_master_hash")
            
            if not stored_hash:
                print("❌ Hash master absent (vault corrompu)")
                return False
            
            if not self.crypto.verify_password_argon2(master_password, stored_hash):
                self._login_attempts += 1
                backoff = LOGIN_ATTEMPT_BACKOFF[min(self._login_attempts - 1, len(LOGIN_ATTEMPT_BACKOFF) - 1)]
                print(f"❌ Mot de passe incorrect. Attendre {backoff}s...")
                time.sleep(backoff)
                return False
            
            key = self.crypto.derive_key_argon2(master_password)
            self.fernet = Fernet(key)
            self.master_hash = stored_hash
            self._login_attempts = 0
            
            if self._load_vault():
                self.session.update_activity()
                return True
            return False
        
        except InvalidToken:
            self._login_attempts += 1
            print(f"❌ Неверный мастер-пароль")
            return False
        except Exception as e:
            print(f"❌ Ошибка при разблокировке: {e}")
            return False
    
    def _verify_vault_integrity(self, encrypted_data: bytes):
        hmac_file = DATA_DIR / "vault.hmac"
        if hmac_file.exists():
            stored_hmac = hmac_file.read_text().strip()
            if not self.crypto.verify_hmac(encrypted_data, stored_hmac):
                raise ValueError("⚠️ INTÉGRITÉ DU VAULT COMPROMISE! Fichier modifié.")
    
    def _load_vault(self) -> bool:
        if not DATA_FILE.exists():
            self.vault = {
                "_format_version": VAULT_FORMAT_VERSION,
                "_created": datetime.now().isoformat()
            }
            return True
        
        try:
            encrypted_data = DATA_FILE.read_bytes()
            self._verify_vault_integrity(encrypted_data)
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.vault = json.loads(decrypted_data.decode())
            return True
        except InvalidToken:
            return False
        except Exception as e:
            print(f"Ошибка загрузки: {e}")
            return False
    
    def _save_vault(self):
        try:
            if DATA_FILE.exists():
                backup_file = BACKUP_DIR / f"vault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
                shutil.copy2(DATA_FILE, backup_file)
                backups = sorted(BACKUP_DIR.glob("vault_*.enc"))
                for old_backup in backups[:-10]:
                    old_backup.unlink()
            
            data = json.dumps(self.vault, ensure_ascii=False, indent=2)
            encrypted_data = self.fernet.encrypt(data.encode())
            
            temp_file = DATA_FILE.with_suffix('.tmp')
            temp_file.write_bytes(encrypted_data)
            temp_file.replace(DATA_FILE)
            
            hmac_value = self.crypto.compute_hmac(encrypted_data)
            (DATA_DIR / "vault.hmac").write_text(hmac_value)
            
            DATA_FILE.chmod(0o600)
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")
            raise
    
    def lock(self):
        self.fernet = None
        self.master_hash = None
        self.vault = {}
        
        self._clear_clipboard()
        
        self.session.stop()
        print("\n🔒 Vault verrouillé")
    
    def _clear_clipboard(self):
        try:
            import pyperclip
            current = pyperclip.paste()
            if current and len(current) < 256:
                pyperclip.copy("")
        except:
            pass
    
    def add_password(self, service: str, username: str, password: str, notes: str = ""):
        self.session.update_activity()
        
        # generate and keep the raw key, Fernet object doesn't expose key attribute
        key = self.crypto.create_fernet_key()
        pwd_fernet = Fernet(key)
        encrypted_pwd = pwd_fernet.encrypt(password.encode()).decode()
        key_for_pwd = key.decode()
        
        self.vault[service] = {
            "username": username,
            "password": encrypted_pwd,
            "password_key": key_for_pwd,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        self._save_vault()
        print(f"✓ Mot de passe pour '{service}' sauvegardен")
    
    def get_password(self, service: str) -> dict | None:
        self.session.update_activity()
        
        if service not in self.vault or service.startswith("_"):
            return None
        
        entry = self.vault[service]
        try:
            pwd_fernet = Fernet(entry["password_key"].encode())
            decrypted_pwd = pwd_fernet.decrypt(entry["password"].encode()).decode()
            
            return {
                "username": entry.get("username"),
                "password": decrypted_pwd,
                "notes": entry.get("notes"),
                "created": entry.get("created"),
                "modified": entry.get("modified")
            }
        except Exception as e:
            print(f"⚠️ Ошибка расшифровки: {e}")
            return None
    
    def delete_password(self, service: str) -> bool:
        self.session.update_activity()
        
        if service in self.vault and not service.startswith("_"):
            del self.vault[service]
            self._save_vault()
            print(f"✓ Mot de passe pour '{service}' supprimé")
            return True
        return False
    
    def list_services(self) -> list:
        self.session.update_activity()
        return [k for k in self.vault.keys() if not k.startswith("_")]
    
    def search(self, query: str) -> list:
        self.session.update_activity()
        query = query.lower()
        return [k for k in self.vault.keys() 
                if not k.startswith("_") and query in k.lower()]
    
    def generate_password(self, length: int = 16, use_special: bool = True) -> str:
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        if use_special:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        password += [secrets.choice(chars) for _ in range(length - len(password))]
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)


def copy_to_clipboard(text: str, clear_after: int = CLIPBOARD_TIMEOUT):
    try:
        import pyperclip
        pyperclip.copy(text)
        print(f"✓ Copié dans le clipboard (nettoyage dans {clear_after}s)")
        
        def clear_clipboard():
            time.sleep(clear_after)
            try:
                current = pyperclip.paste()
                if current == text:
                    pyperclip.copy("")
            except:
                pass
        
        threading.Thread(target=clear_clipboard, daemon=True).start()
    except ImportError:
        print("⚠️ pyperclip non installé")
    except Exception as e:
        print(f"⚠️ Ошибка буфера обмена: {e}")


def print_header():
    print("\n" + "="*60)
    print("🔐 CLI Password Manager - SECURITY ENHANCED EDITION")
    print("="*60)


def print_menu():
    print("\n┌────────────────────────────────────────┐")
    print("│  Commandes:                            │")
    print("├────────────────────────────────────────┤")
    print("│  add     - Ajouter mot de passe        │")
    print("│  get     - Obtenir mot de passe        │")
    print("│  list    - Lister services             │")
    print("│  search  - Rechercher                  │")
    print("│  delete  - Supprimer mot de passe      │")
    print("│  gen     - Générer mot de passe        │")
    print("│  lock    - Verrouiller                 │")
    print("│  exit    - Quitter                     │")
    print("└────────────────────────────────────────┘")


def main():
    pm = PasswordManager()
    
    print_header()
    
    if not pm.is_initialized():
        print("\n📝 Первый запуск. Создайте мастер-пароль.")
        print("   ⚠️  Мин 10 символов: заглавная, строчная, цифра")
        print("   ⚠️  Запомните — восстановление невозможно")
        
        while True:
            password1 = getpass.getpass("\nMaster-password: ")
            password2 = getpass.getpass("Confirmation: ")
            
            if password1 != password2:
                print("❌ Les mots de passe ne correspondent pas")
                continue
            
            if pm.initialize(password1):
                break
    else:
        attempts = 0
        while attempts < LOGIN_ATTEMPTS:
            password = getpass.getpass("\n🔑 Master-password: ")
            
            if pm.unlock(password):
                print("✓ Vault déverrouillé")
                break
            else:
                attempts += 1
                if attempts >= LOGIN_ATTEMPTS:
                    print("❌ Trop d'essais. Sortie.")
                    sys.exit(1)
    
    pm.session.start_timeout_checker(pm.lock)
    
    while True:
        print_menu()
        
        try:
            cmd = input("\n> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            pm.lock()
            break
        
        if pm.session.check_timeout():
            pm.lock()
            print("⏱️ Session expirée")
            password = getpass.getpass("\n🔑 Master-password: ")
            if not pm.unlock(password):
                print("❌ Mot de passe incorrect")
                continue
            print("✓ Vault déverrouillé")
        
        if cmd == "add":
            service = input("Service (Google, GitHub...): ").strip()
            if not service:
                print("⚠️ Service vide")
                continue
            
            username = input("Login/Email: ").strip()
            
            gen = input("Générer? (y/n): ").strip().lower()
            if gen == 'y':
                try:
                    length = int(input("Longueur (défaut 16): ").strip() or "16")
                except ValueError:
                    length = 16
                password = pm.generate_password(length)
                print(f"Généré: {password}")
                copy_to_clipboard(password)
            else:
                password = getpass.getpass("Mot de passe: ")
            
            notes = input("Notes (optionnel): ").strip()
            pm.add_password(service, username, password, notes)
        
        elif cmd == "get":
            service = input("Service: ").strip()
            data = pm.get_password(service)
            
            if data:
                print(f"\n┌─ {service} ─────────────────────")
                print(f"│ Login:    {data['username']}")
                print(f"│ Password: ••••••••• (copié)")
                if data.get('notes'):
                    print(f"│ Notes:    {data['notes']}")
                print(f"│ Modified: {data['modified'][:10]}")
                print("└" + "─" * 40)
                copy_to_clipboard(data['password'])
                
                def auto_hide():
                    time.sleep(PASSWORD_SHOW_TIMEOUT)
                    print("🔒 Mot de passe masqué")
                threading.Thread(target=auto_hide, daemon=True).start()
            else:
                print(f"⚠️ '{service}' non trouvé")
        
        elif cmd == "list":
            services = pm.list_services()
            if services:
                print(f"\n📋 Services ({len(services)}):")
                for i, s in enumerate(sorted(services), 1):
                    print(f"   {i}. {s}")
            else:
                print("📭 Aucun service")
        
        elif cmd == "search":
            query = input("Recherche: ").strip()
            results = pm.search(query)
            if results:
                print(f"\n🔍 Trouvés ({len(results)}):")
                for s in results:
                    print(f"   • {s}")
            else:
                print("❌ Aucun résultat")
        
        elif cmd == "delete":
            service = input("Service à supprimer: ").strip()
            confirm = input(f"Confirmer suppression de '{service}'? (y/n): ").strip().lower()
            if confirm == 'y':
                if not pm.delete_password(service):
                    print(f"⚠️ '{service}' non trouvé")
        
        elif cmd == "gen":
            try:
                length = int(input("Longueur (défaut 16): ").strip() or "16")
            except ValueError:
                length = 16
            
            password = pm.generate_password(length)
            print(f"\n🎲 Généré: {password}")
            copy_to_clipboard(password)
        
        elif cmd == "lock":
            pm.lock()
            password = getpass.getpass("\n🔑 Master-password: ")
            if not pm.unlock(password):
                print("❌ Incorrect")
                sys.exit(1)
            print("✓ Déverrouillé")
        
        elif cmd == "exit":
            pm.lock()
            print("👋 Au revoir!")
            break
        
        else:
            print("⚠️ Commande inconnue")


if __name__ == "__main__":
    main()
