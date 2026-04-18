#!/usr/bin/env python3
"""
CLI Password Manager
Локальный менеджер паролей с шифрованием Fernet
"""

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
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken


# Константы
DATA_DIR = Path.home() / ".password_manager"
DATA_FILE = DATA_DIR / "vault.enc"
SALT_FILE = DATA_DIR / "salt"
SESSION_TIMEOUT = 300  # 5 минут таймаут сессии


class SessionManager:
    """Управление таймаутом сессии"""
    
    def __init__(self, timeout: int = SESSION_TIMEOUT):
        self.timeout = timeout
        self.last_activity = time.time()
        self.is_active = True
        self._lock = threading.Lock()
        self._timer_thread = None
    
    def update_activity(self):
        """Обновить время последней активности"""
        with self._lock:
            self.last_activity = time.time()
    
    def check_timeout(self) -> bool:
        """Проверить, истёк ли таймаут"""
        with self._lock:
            return time.time() - self.last_activity > self.timeout
    
    def start_timeout_checker(self, on_timeout_callback):
        """Запустить фоновую проверку таймаута"""
        def checker():
            while self.is_active:
                time.sleep(10)  # Проверка каждые 10 секунд
                if self.check_timeout():
                    on_timeout_callback()
                    break
        
        self._timer_thread = threading.Thread(target=checker, daemon=True)
        self._timer_thread.start()
    
    def stop(self):
        """Остановить менеджер сессии"""
        self.is_active = False


class PasswordManager:
    """Основной класс менеджера паролей"""
    
    def __init__(self):
        self.fernet = None
        self.vault = {}
        self.session = SessionManager()
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        """Создать директорию для данных если её нет"""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    def _get_salt(self) -> bytes:
        """Получить или создать соль для ключа"""
        if SALT_FILE.exists():
            return SALT_FILE.read_bytes()
        else:
            salt = os.urandom(32)
            SALT_FILE.write_bytes(salt)
            return salt
    
    def _derive_key(self, master_password: str) -> bytes:
        """Получить ключ шифрования из мастер-пароля"""
        salt = self._get_salt()
        # Используем PBKDF2 для получения ключа
        key = hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode(),
            salt,
            iterations=100000,
            dklen=32
        )
        return base64.urlsafe_b64encode(key)
    
    def _load_vault(self) -> bool:
        """Загрузить зашифрованное хранилище"""
        if not DATA_FILE.exists():
            self.vault = {}
            return True
        
        try:
            encrypted_data = DATA_FILE.read_bytes()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.vault = json.loads(decrypted_data.decode())
            return True
        except InvalidToken:
            return False
        except Exception as e:
            print(f"Ошибка загрузки хранилища: {e}")
            return False
    
    def _save_vault(self):
        """Сохранить хранилище в зашифрованном виде"""
        data = json.dumps(self.vault, ensure_ascii=False, indent=2)
        encrypted_data = self.fernet.encrypt(data.encode())
        DATA_FILE.write_bytes(encrypted_data)
    
    def is_initialized(self) -> bool:
        """Проверить, инициализирован ли менеджер"""
        return DATA_FILE.exists()
    
    def initialize(self, master_password: str) -> bool:
        """Инициализировать новое хранилище"""
        if self.is_initialized():
            print("Хранилище уже существует!")
            return False
        
        key = self._derive_key(master_password)
        self.fernet = Fernet(key)
        self.vault = {"_created": datetime.now().isoformat()}
        self._save_vault()
        print("✓ Хранилище успешно создано!")
        return True
    
    def unlock(self, master_password: str) -> bool:
        """Разблокировать хранилище"""
        key = self._derive_key(master_password)
        self.fernet = Fernet(key)
        
        if self._load_vault():
            self.session.update_activity()
            return True
        else:
            self.fernet = None
            return False
    
    def lock(self):
        """Заблокировать хранилище"""
        self.fernet = None
        self.vault = {}
        self.session.stop()
        print("\n🔒 Хранилище заблокировано")
    
    def add_password(self, service: str, username: str, password: str, notes: str = ""):
        """Добавить новый пароль"""
        self.session.update_activity()
        
        self.vault[service] = {
            "username": username,
            "password": password,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        self._save_vault()
        print(f"✓ Пароль для '{service}' сохранён")
    
    def get_password(self, service: str) -> dict | None:
        """Получить пароль по имени сервиса"""
        self.session.update_activity()
        
        if service in self.vault and service != "_created":
            return self.vault[service]
        return None
    
    def delete_password(self, service: str) -> bool:
        """Удалить пароль"""
        self.session.update_activity()
        
        if service in self.vault and service != "_created":
            del self.vault[service]
            self._save_vault()
            print(f"✓ Пароль для '{service}' удалён")
            return True
        return False
    
    def list_services(self) -> list:
        """Список всех сервисов"""
        self.session.update_activity()
        return [k for k in self.vault.keys() if k != "_created"]
    
    def search(self, query: str) -> list:
        """Поиск по сервисам"""
        self.session.update_activity()
        query = query.lower()
        return [k for k in self.vault.keys() 
                if k != "_created" and query in k.lower()]
    
    def generate_password(self, length: int = 16, use_special: bool = True) -> str:
        """Генерация безопасного пароля"""
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Гарантируем наличие разных типов символов
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        if use_special:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Добавляем остальные символы
        password += [secrets.choice(chars) for _ in range(length - len(password))]
        
        # Перемешиваем
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)


def copy_to_clipboard(text: str, clear_after: int = 30):
    """Копировать в буфер обмена с автоочисткой"""
    try:
        import pyperclip
        pyperclip.copy(text)
        print(f"✓ Скопировано в буфер обмена (очистится через {clear_after} сек)")
        
        # Очистка буфера через заданное время
        def clear_clipboard():
            time.sleep(clear_after)
            try:
                current = pyperclip.paste()
                if current == text:
                    pyperclip.copy("")
                    print("\n🧹 Буфер обмена очищен")
            except:
                pass
        
        thread = threading.Thread(target=clear_clipboard, daemon=True)
        thread.start()
        
    except ImportError:
        print("⚠ pyperclip не установлен. Установите: pip install pyperclip")
    except Exception as e:
        print(f"⚠ Ошибка копирования: {e}")


def print_header():
    """Вывести заголовок"""
    print("\n" + "="*50)
    print("🔐 CLI Password Manager")
    print("="*50)


def print_menu():
    """Вывести меню"""
    print("\n┌─────────────────────────────────────┐")
    print("│  Команды:                           │")
    print("├─────────────────────────────────────┤")
    print("│  add     - Добавить пароль          │")
    print("│  get     - Получить пароль          │")
    print("│  list    - Список сервисов          │")
    print("│  search  - Поиск                    │")
    print("│  delete  - Удалить пароль           │")
    print("│  gen     - Генерировать пароль      │")
    print("│  lock    - Заблокировать            │")
    print("│  exit    - Выход                    │")
    print("└─────────────────────────────────────┘")


def main():
    pm = PasswordManager()
    
    print_header()
    
    # Инициализация или разблокировка
    if not pm.is_initialized():
        print("\n📝 Первый запуск. Создайте мастер-пароль.")
        print("   (Запомните его! Восстановление невозможно)")
        
        while True:
            password1 = getpass.getpass("\nВведите мастер-пароль: ")
            if len(password1) < 8:
                print("⚠ Пароль должен быть минимум 8 символов")
                continue
            
            password2 = getpass.getpass("Подтвердите мастер-пароль: ")
            
            if password1 != password2:
                print("⚠ Пароли не совпадают!")
                continue
            
            pm.initialize(password1)
            break
    else:
        attempts = 3
        while attempts > 0:
            password = getpass.getpass("\n🔑 Введите мастер-пароль: ")
            
            if pm.unlock(password):
                print("✓ Хранилище разблокировано")
                break
            else:
                attempts -= 1
                if attempts > 0:
                    print(f"⚠ Неверный пароль! Осталось попыток: {attempts}")
                else:
                    print("❌ Превышено количество попыток. Выход.")
                    sys.exit(1)
    
    # Запуск таймера сессии
    pm.session.start_timeout_checker(pm.lock)
    
    # Главный цикл
    while True:
        print_menu()
        
        try:
            cmd = input("\n> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            pm.lock()
            break
        
        # Проверка таймаута
        if pm.session.check_timeout():
            pm.lock()
            print("⏱ Сессия истекла. Требуется повторная авторизация.")
            password = getpass.getpass("\n🔑 Введите мастер-пароль: ")
            if not pm.unlock(password):
                print("❌ Неверный пароль!")
                continue
            print("✓ Хранилище разблокировано")
        
        if cmd == "add":
            service = input("Название сервиса: ").strip()
            if not service:
                print("⚠ Название не может быть пустым")
                continue
            
            username = input("Логин/Email: ").strip()
            
            gen_pass = input("Сгенерировать пароль? (y/n): ").strip().lower()
            if gen_pass == 'y':
                try:
                    length = int(input("Длина пароля (по умолчанию 16): ").strip() or "16")
                except ValueError:
                    length = 16
                password = pm.generate_password(length)
                print(f"Сгенерированный пароль: {password}")
                copy_to_clipboard(password)
            else:
                password = getpass.getpass("Пароль: ")
            
            notes = input("Заметки (опционально): ").strip()
            
            pm.add_password(service, username, password, notes)
        
        elif cmd == "get":
            service = input("Название сервиса: ").strip()
            data = pm.get_password(service)
            
            if data:
                print(f"\n┌─ {service} ─────────────────────")
                print(f"│ Логин:    {data['username']}")
                print(f"│ Пароль:   {'*' * 8} (скопирован)")
                if data.get('notes'):
                    print(f"│ Заметки:  {data['notes']}")
                print(f"│ Изменён:  {data['modified'][:10]}")
                print("└" + "─" * 35)
                
                copy_to_clipboard(data['password'])
            else:
                print(f"⚠ Сервис '{service}' не найден")
        
        elif cmd == "list":
            services = pm.list_services()
            if services:
                print(f"\n📋 Сохранённые сервисы ({len(services)}):")
                for i, s in enumerate(sorted(services), 1):
                    print(f"   {i}. {s}")
            else:
                print("📭 Хранилище пусто")
        
        elif cmd == "search":
            query = input("Поиск: ").strip()
            results = pm.search(query)
            if results:
                print(f"\n🔍 Найдено ({len(results)}):")
                for s in results:
                    print(f"   • {s}")
            else:
                print("Ничего не найдено")
        
        elif cmd == "delete":
            service = input("Название сервиса для удаления: ").strip()
            confirm = input(f"Удалить '{service}'? (y/n): ").strip().lower()
            if confirm == 'y':
                if not pm.delete_password(service):
                    print(f"⚠ Сервис '{service}' не найден")
        
        elif cmd == "gen":
            try:
                length = int(input("Длина пароля (по умолчанию 16): ").strip() or "16")
            except ValueError:
                length = 16
            
            password = pm.generate_password(length)
            print(f"\n🎲 Сгенерированный пароль: {password}")
            copy_to_clipboard(password)
        
        elif cmd == "lock":
            pm.lock()
            password = getpass.getpass("\n🔑 Введите мастер-пароль для разблокировки: ")
            if not pm.unlock(password):
                print("❌ Неверный пароль!")
                sys.exit(1)
            print("✓ Хранилище разблокировано")
        
        elif cmd == "exit":
            pm.lock()
            print("👋 До свидания!")
            break
        
        else:
            print("⚠ Неизвестная команда")


if __name__ == "__main__":
    main()
