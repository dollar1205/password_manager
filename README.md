# Zero-Knowledge Password Manager
URL : https://paswordmanager.duckdns.org
Secure client-server password manager with a `PySide6` desktop client and `FastAPI` backend.

The design follows a zero-knowledge model:

- The server never receives plaintext passwords.
- All key derivation, encryption, and decryption happen only on the client.
- The server stores only a salt, an encrypted vault blob, metadata, and a hash of the API token used for transport authentication.

## Project Structure

```text
.
├── client/
│   ├── app/
│   │   ├── api_client.py
│   │   ├── config.py
│   │   ├── crypto.py
│   │   ├── gui/
│   │   │   ├── dialogs.py
│   │   │   ├── styles.py
│   │   │   └── windows.py
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── password_generator.py
│   │   ├── secure_memory.py
│   │   └── storage.py
│   ├── main.py
│   └── requirements.txt
├── server/
│   ├── app/
│   │   ├── auth.py
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   └── security.py
│   ├── .env.example
│   ├── main.py
│   └── requirements.txt
├── README.md
├── SECURITY.md
└── requirements.txt
```

Legacy standalone scripts from the original repository are still present at the root, but the new secure architecture is implemented under `client/` and `server/`.

## Security Architecture

### Client-side cryptography

1. User enters a master password.
2. Client derives a 32-byte master key using `Argon2id`.
3. Client derives subkeys from the master key with `HKDF-SHA256`:
   - `vault-encryption`
   - `profile-api-token`
4. Vault data is encrypted with `AES-256-GCM`.
5. The encrypted vault blob is uploaded to the server.

### Server-side storage

The backend stores:

- `user_id`
- `salt` as base64
- `encrypted_vault` as base64
- `vault_version`
- `updated_at`
- `token_hash` for bearer-token authentication

The backend never stores:

- plaintext passwords
- derived keys
- decrypted vault contents

### Local profile

The client stores a local profile at `~/.zk_password_manager/profile.json` containing:

- `user_id`
- `server_url`
- `salt_b64`
- an `AES-GCM` encrypted API token
- the last encrypted vault blob for offline unlock
- local vault version metadata

The API token is encrypted locally under a key derived from the master password.

## Features

- `PySide6` desktop GUI
- Master password login
- `Argon2id` local key derivation
- `AES-256-GCM` vault encryption
- Encrypted-at-rest local cache and remote storage
- Add, edit, delete, search, reveal, and copy entries
- Clipboard auto-clear after 15 seconds
- Auto-lock after inactivity
- Secure password generator
- FastAPI backend with rate limiting
- Vault versioning and conflict detection
- Basic anti-debug detection
- Improved text rendering:
  - `Qt` high-DPI rounding policy set to `PassThrough`
  - application font uses `PreferAntialias`
  - `Segoe UI` on Windows to avoid pixelated text

## Backend Setup

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install backend dependencies

```powershell
pip install -r server\requirements.txt
```

### 3. Configure environment

```powershell
Copy-Item server\.env.example server\.env
```

Optional production settings:

- `PM_DATABASE_URL=postgresql+psycopg://...` for PostgreSQL
- `PM_REQUIRE_HTTPS=true`
- `PM_ALLOW_INSECURE_LOCALHOST=false`

### 4. Start the API

Production-style TLS:

```powershell
uvicorn server.app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile .\certs\server.crt --ssl-keyfile .\certs\server.key
```

Local development on localhost only:

```powershell
$env:PM_ALLOW_INSECURE_LOCALHOST="true"
uvicorn server.app.main:app --host 127.0.0.1 --port 8000
```

## Client Setup

### 1. Install client dependencies

```powershell
pip install -r client\requirements.txt
```

### 2. Start the desktop app

```powershell
python -m client.main
```

### 3. First run

1. Open the `Create New Account` tab.
2. Enter the server URL.
3. Choose a strong master password.
4. The server returns a random salt and API token.
5. The client derives the master key locally, encrypts the API token locally, creates an empty encrypted vault, and uploads it.

### 4. Subsequent runs

1. Open the `Unlock Existing Vault` tab.
2. Enter the master password.
3. The client derives the master key locally.
4. The client decrypts the local API token, fetches the encrypted vault, and decrypts it locally.

## API Endpoints

- `POST /register`
  - Creates a new user
  - Generates a random salt
  - Generates a random API token
  - Stores only the API token hash

- `POST /upload`
  - Requires `Authorization: Bearer <token>`
  - Stores the encrypted vault blob
  - Increments `vault_version`
  - Rejects stale versions with `409 Conflict`

- `GET /vault`
  - Requires `Authorization: Bearer <token>`
  - Returns the current `salt`, encrypted vault blob, and version

## Root Requirements Convenience File

You can install everything at once with:

```powershell
pip install -r requirements.txt
```

## Security Notes

- `AES-GCM` already provides ciphertext integrity.
- The server validates only metadata, not vault contents.
- Local caching is encrypted and uses the same zero-knowledge vault blob format as the server.
- Clipboard contents are cleared automatically, but a compromised host OS can still inspect them while present.
- Python cannot guarantee perfect memory zeroization for all temporary immutable objects. The implementation uses `bytearray` and explicit wiping where feasible, but this remains a language-level limitation.

More detail is in [SECURITY.md](SECURITY.md).
