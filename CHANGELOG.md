# CHANGELOG

All notable changes to this project will be documented in this file.

## [1.1.0] - 2025-01-30 🔐 SECURITY ENHANCED EDITION

### 🔒 Security Improvements

#### Encryption & Key Derivation
- ✨ **Migrated from PBKDF2 to Argon2id** - CPU + memory-hard algorithm resistant to GPU attacks
- ✨ **Double-key architecture** - Master key (Argon2) + per-record Fernet keys
- ✨ **Per-password encryption** - Each password encrypted with unique Fernet key, not stored in plaintext
- ✨ **HMAC-SHA256 integrity checking** - Detect any modification of vault.enc
- ✨ **Secure key derivation** - 100 PBKDF2 iterations after Argon2id

#### Memory Protection
- 🧠 **On-demand decryption** - Passwords only decrypted when needed, not kept in memory
- 🧠 **Immediate wipe** - Variables containing secrets cleared immediately after use
- 🧠 **Minimal secret lifetime** - Auto-hide password after 5 seconds (GUI)
- 🧠 **Clipboard auto-clear** - 10-second timeout before clearing copied password

#### Session Management & Lockdown
- ⏱️ **Reduced session timeout** from 300s → 120s (2 minutes)
- 🔒 **Auto-lock on inactivity** - Immediately purges encryption keys from memory
- 🔒 **Clipboard clearance on lock** - Removes sensitive data from clipboard
- 🔒 **Forced re-authentication** - After timeout, password re-entry required

#### Authorization & Rate Limiting
- 🚫 **Login attempt limiting** - Maximum 3 attempts
- 🚫 **Exponential backoff** - 1s → 2s → 4s delays between attempts
- 🚫 **Minimum password strength** - 10+ characters, uppercase + lowercase + digits
- 🚫 **Argon2 verification** - Compare against stored password hash

#### GUI/UX Security
- 👀 **Password visibility timeout** - Auto-hides after 5 seconds in view mode
- 👀 **Manual copy button** - User-controlled, not auto-copy (safer)
- 👀 **Clean logging** - No sensitive data in debug output
- 👀 **Widget memory** - Passwords not stored in UI state

#### Debugger & Runtime Protection
- 🔍 **Debugger detection** - `sys.gettrace()` check at startup
- 🔍 **Per-record decryption** - Whole vault not decrypted at once
- 🔍 **Clipboard verification** - Only clear if content unchanged

#### Storage & Backup
- 💾 **Atomic writes** - Temp file + rename pattern, prevents corruption
- 💾 **Automatic backups** - Stores up to 10 snapshots in ~/.password_manager/backups/
- 💾 **Vault versioning** - _format_version field for future migrations
- 💾 **Integrity checks** - HMAC validation on every load
- 💾 **Permission enforcement** - Files created with 0o600 (owner-only)

### 📚 Documentation
- 📖 Added comprehensive **SECURITY.md** with threat model
  - Detailed "What's Protected" vs "What's NOT Protected"
  - Best practices and recommendations
  - Technical details and algorithm specs
  - Audit history
  
- 📖 Added **CHANGELOG.md** (this file)
- 📖 Updated **README.md** with security warnings and upgrade instructions

### 🏗️ Code Changes

#### New Files
- `password_manager_secure.py` - CLI version with all security enhancements
- `gui_app.py` - GUI version with all security enhancements
- `SECURITY.md` - Security documentation and threat model
- `CHANGELOG.md` - Version history

#### Security Classes
- `SecurityUtils` - Password validation, debugger detection
- `CryptoManager` - Centralized cryptography management
  - Argon2id derivation
  - HMAC computation & verification
  - Per-record key generation

### 🔄 Breaking Changes
⚠️ **WARNING:** Old v1.0 vaults (PBKDF2-encrypted) are NOT compatible with v1.1.0

**Migration Path:**
1. Export all passwords from v1.0 CLI
2. Delete ~/.password_manager/* (except backups)
3. Create new vault with v1.1.0
4. Re-import passwords

### ⚙️ Configuration Changes

| Setting | v1.0 | v1.1.0 | Reason |
|---------|------|--------|--------|
| SESSION_TIMEOUT | 300s | 120s | Shorter exposure |
| PBKDF2 iterations | 100,000 | - (Argon2id now) | Better security |
| MIN_PASSWORD_LENGTH | 8 | 10 | Stronger master pwd |
| LOGIN_ATTEMPTS | unlimited | 3 | Rate limiting |
| CLIPBOARD_TIMEOUT | 30s | 10s | Less time in clipboard |
| PASSWORD_SHOW_TIMEOUT | - | 5s | Auto-hide in GUI |

### 📦 Dependencies

**New:**
- `argon2-cffi>=25.1.0` - Argon2id implementation
- `psutil>=5.9.0` - Process inspection (optional, for PIN checks)
- `zxcvbn>=4.4.28` - Password strength estimator (optional)
- `cryptography==43.0.0` - Updated for security patches

**Updated:**
- `cryptography` 42.0.5 → 43.0.0 (security)

### ✅ Testing Recommendations

- [x] Test new vault creation with Argon2
- [x] Test password encryption/decryption per-record
- [x] Test HMAC integrity checking (try modifying vault.enc)
- [x] Test login rate limiting (3 attempts + backoff)
- [x] Test session timeout (120 seconds inactivity)
- [x] Test clipboard auto-clear
- [x] Test password auto-hide (GUI)
- [x] Verify backups created in ~/.password_manager/backups/
- [x] Check permission enforcement (chmod 600)

### 🐛 Known Issues / Limitations

- ❌ No recovery if master password is forgotten (by design)
- ❌ Python source code can be decompiled (.pyc, .pyo)
- ❌ PyInstaller binaries can be unpacked
- ❌ No obfuscation - source openly readable
- ❌ Cannot protect against:
  - RAT (Remote Access Trojan) with root access
  - Keylogger at OS level
  - Memory dump with administrator privileges
  - Physical attacks / cold boot
  - Compromised OS

### 🔐 Security Audit Notes

- [x] Migrated to Argon2id (CPU + memory-hard)
- [x] Implemented double-key architecture
- [x] Added HMAC-SHA256 for vault integrity
- [x] Implemented per-password encryption
- [x] Reduced session timeout to 120s
- [x] Added exponential backoff on login
- [x] Added automatic backup system
- [x] Added debugger detection
- [x] Implemented atomic file writes
- [x] Added security documentation (SECURITY.md)

### 📋 Checklist for Future Releases

- [ ] Add support for hardware security keys (FIDO2)
- [ ] Implement vault encryption with master key + recovery codes
- [ ] Add export/import with encrypted format
- [ ] Add database backend option (SQLite encrypted)
- [ ] Add cloud sync with E2E encryption
- [ ] Add audit logging (without sensitive data)
- [ ] Add multi-user support with permissions
- [ ] Add password strength meter during generation
- [ ] Add breach checking (HaveIBeenPwned API)
- [ ] Implement CSPRNG for random generation

---

## [1.0.0] - 2025-01-15

### Initial Release
- Basic password storage with Fernet encryption
- PBKDF2 key derivation (100k iterations)
- CLI interface
- GUI interface with customtkinter
- Session timeout (5 minutes)
- Password generation
- Search functionality
- PyInstaller build support

### Limitations (Fixed in 1.1.0)
- ❌ Used weak PBKDF2 instead of Argon2id
- ❌ Passwords stored in plaintext in vault
- ❌ No HMAC integrity checking
- ❌ Long session timeout (300s)
- ❌ No rate limiting on login
- ❌ No backup system
- ❌ No minimum password requirements

---

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** - Breaking changes (new vault format)
- **MINOR** - New features (backward compatible)
- **PATCH** - Bug fixes

---

## Legend

- ✨ Feature
- 🔒 Security
- 🧠 Memory/Performance
- ⏱️ Timing
- 📖 Documentation
- 🐛 Bug fix
- ⚠️ Breaking change
- 🔄 Migration
- ✅ Completed
- ❌ Not implemented
