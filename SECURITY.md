# Security Model

## Goals

- Server never sees plaintext passwords.
- Server never derives user encryption keys.
- All vault encryption and decryption happen on the client.
- Remote storage contains only opaque encrypted blobs.

## Cryptographic Flow

1. The backend creates a random 32-byte salt during registration.
2. The client derives a master key with `Argon2id`.
3. The client derives context-specific subkeys with `HKDF-SHA256`.
4. The vault is encrypted with `AES-256-GCM`.
5. The encrypted vault envelope is base64-encoded and uploaded.

## Why The Server Cannot Read Vault Data

The server receives:

- `salt`
- `encrypted_vault`
- bearer token

The server does not receive:

- master password
- master key
- decrypted vault JSON

The bearer token is only for transport authentication and is unrelated to the encryption key hierarchy.

## Authentication Design

- On registration, the server creates a random API token.
- The server stores only `SHA-256(api_token)`.
- The raw API token is returned once to the client.
- The client encrypts the API token locally with a key derived from the master password.

This keeps server-side auth separate from vault encryption while still allowing a zero-knowledge model.

## Integrity And Versioning

- `AES-GCM` provides authenticated encryption for the vault.
- The backend tracks `vault_version`.
- Uploads require `base_version`.
- Stale clients receive `409 Conflict`.

This prevents silent overwrite of a newer vault.

## Memory Handling

The client attempts to reduce long-lived secret exposure by:

- storing active secrets in `bytearray` where practical
- wiping derived keys on lock
- wiping per-entry password buffers when entries are deleted or the session is locked
- minimizing plaintext persistence outside the active session

## Limits Of Python

Python is not a hardened memory-safe secret-management runtime.

Important limits:

- immutable `str` objects cannot be reliably zeroized
- temporary copies may exist inside the interpreter or C extensions
- GUI widgets and clipboard integration necessarily materialize plaintext briefly

This means the system is strong against a malicious server and at-rest theft, but it is not a defense against a fully compromised local host, memory dump, kernel malware, or keylogger.

## Transport Security

- API rejects non-HTTPS requests except optional localhost development mode
- rate limiting is enforced with `slowapi`
- recommended deployment is behind TLS with a reverse proxy or direct `uvicorn` TLS termination

## Optional Hardening Not Yet Implemented

- certificate pinning
- TOTP-based second factor
- hardware-backed local secret storage
- secure enclave or TPM integration

These can be layered on later without changing the zero-knowledge vault format.
