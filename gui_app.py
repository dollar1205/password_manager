

import customtkinter as ctk
from tkinter import messagebox
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

import sys

def resource_path(relative_path):
    base = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base, relative_path)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DATA_DIR = Path.home() / ".password_manager"
DATA_FILE = DATA_DIR / "vault.enc"
SALT_FILE = DATA_DIR / "salt"
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
        
        self.pm = PasswordManager()
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
            self.auth_hint.configure(text="Минимум 8 символов. Запомните — восстановление невозможно.")
        
        self.auth_btn.pack(fill='x', pady=(8, 0))
        
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
        
        self.auth_confirm_frame = ctk.CTkFrame(form, fg_color='transparent')
        ctk.CTkLabel(self.auth_confirm_frame, text="Подтвердите пароль", font=('Segoe UI', 13), 
                     text_color=COLORS['text_secondary'], anchor='w').pack(fill='x', pady=(0, 8))
        self.auth_confirm = ctk.CTkEntry(self.auth_confirm_frame, placeholder_text="Повторите пароль", 
                                          show="●", height=48, font=('Segoe UI', 14), corner_radius=12)
        self.auth_confirm.pack(fill='x')
        self.auth_confirm.bind('<Return>', lambda e: self._handle_auth())
        
        self.auth_btn = AnimatedButton(form, text="Разблокировать", height=48, font=('Segoe UI', 14, 'bold'),
                                        corner_radius=12, fg_color=COLORS['accent'], command=self._handle_auth)
        
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
        
        if self.pm.is_initialized():
            if self.pm.unlock(password):
                self._show_toast("Хранилище разблокировано", "success")
                self._show_screen('main')
                self.auth_password.delete(0, 'end')
            else:
                self._show_toast("Неверный пароль", "error")
        else:
            confirm = self.auth_confirm.get()
            
            if len(password) < 8:
                self._show_toast("Пароль минимум 8 символов", "error")
                return
            
            if password != confirm:
                self._show_toast("Пароли не совпадают", "error")
                return
            
            if self.pm.initialize(password):
                self.pm.unlock(password)
                self._show_toast("Хранилище создано", "success")
                self._show_screen('main')
                self.auth_password.delete(0, 'end')
                self.auth_confirm.delete(0, 'end')
    
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
        
        self.pm.add(name, username, password, notes)
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
            self.show_pwd_var = not getattr(self, 'show_pwd_var', False)
            self.view_password.configure(text=data['password'] if self.show_pwd_var else "••••••••••••")
            try:
                self.view_show_btn.configure(text="🙈" if self.show_pwd_var else "👁")
            except Exception:
                pass
    
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
    
    def _start_session_timer(self):
        """Запуск таймера сессии"""
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
