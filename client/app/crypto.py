from __future__ import annotations

import base64
import json
import os
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secure_memory import wipe_bytearray


class CryptoError(RuntimeError):
    pass


class ClientCrypto:
    _argon_time_cost = 3
    _argon_memory_cost = 65_536
    _argon_parallelism = max(1, min(4, os.cpu_count() or 1))
    _key_length = 32
    _nonce_length = 12

    def derive_master_key(self, password_buffer: bytearray, salt_b64: str) -> bytearray:
        try:
            salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
            raw_key = hash_secret_raw(
                secret=bytes(password_buffer),
                salt=salt,
                time_cost=self._argon_time_cost,
                memory_cost=self._argon_memory_cost,
                parallelism=self._argon_parallelism,
                hash_len=self._key_length,
                type=Type.ID,
            )
        except Exception as exc:
            raise CryptoError("Unable to derive the master key.") from exc

        return bytearray(raw_key)

    def _derive_subkey(self, master_key: bytearray, purpose: bytes) -> bytearray:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self._key_length,
            salt=None,
            info=purpose,
        )
        return bytearray(hkdf.derive(bytes(master_key)))

    def encrypt_api_token(
        self,
        master_key: bytearray,
        api_token_buffer: bytearray,
        user_id: str,
    ) -> tuple[str, str]:
        profile_key = self._derive_subkey(master_key, b"profile-api-token")
        try:
            nonce = secrets.token_bytes(self._nonce_length)
            ciphertext = AESGCM(bytes(profile_key)).encrypt(
                nonce,
                bytes(api_token_buffer),
                user_id.encode("utf-8"),
            )
            return (
                base64.b64encode(nonce).decode("ascii"),
                base64.b64encode(ciphertext).decode("ascii"),
            )
        except Exception as exc:
            raise CryptoError("Unable to encrypt the local API token.") from exc
        finally:
            wipe_bytearray(profile_key)

    def decrypt_api_token(
        self,
        master_key: bytearray,
        nonce_b64: str,
        ciphertext_b64: str,
        user_id: str,
    ) -> bytearray:
        profile_key = self._derive_subkey(master_key, b"profile-api-token")
        try:
            nonce = base64.b64decode(nonce_b64.encode("ascii"), validate=True)
            ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
            plaintext = AESGCM(bytes(profile_key)).decrypt(
                nonce,
                ciphertext,
                user_id.encode("utf-8"),
            )
            return bytearray(plaintext)
        except Exception as exc:
            raise CryptoError("Invalid master password or corrupt local profile.") from exc
        finally:
            wipe_bytearray(profile_key)

    def encrypt_vault(
        self,
        master_key: bytearray,
        vault_payload: dict[str, object],
        user_id: str,
    ) -> str:
        vault_key = self._derive_subkey(master_key, b"vault-encryption")
        plaintext = bytearray(
            json.dumps(vault_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        try:
            nonce = secrets.token_bytes(self._nonce_length)
            ciphertext = AESGCM(bytes(vault_key)).encrypt(
                nonce,
                bytes(plaintext),
                user_id.encode("utf-8"),
            )
            envelope = {
                "format": 1,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
            return base64.b64encode(
                json.dumps(envelope, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
        except Exception as exc:
            raise CryptoError("Unable to encrypt the vault.") from exc
        finally:
            wipe_bytearray(vault_key)
            wipe_bytearray(plaintext)

    def decrypt_vault(
        self,
        master_key: bytearray,
        encrypted_vault_b64: str,
        user_id: str,
    ) -> dict[str, object]:
        vault_key = self._derive_subkey(master_key, b"vault-encryption")
        plaintext_buffer: bytearray | None = None
        try:
            envelope_raw = base64.b64decode(encrypted_vault_b64.encode("ascii"), validate=True)
            envelope = json.loads(envelope_raw.decode("utf-8"))
            nonce = base64.b64decode(envelope["nonce"].encode("ascii"), validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"].encode("ascii"), validate=True)
            plaintext = AESGCM(bytes(vault_key)).decrypt(
                nonce,
                ciphertext,
                user_id.encode("utf-8"),
            )
            plaintext_buffer = bytearray(plaintext)
            return json.loads(plaintext_buffer.decode("utf-8"))
        except Exception as exc:
            raise CryptoError("Unable to decrypt the vault.") from exc
        finally:
            wipe_bytearray(vault_key)
            wipe_bytearray(plaintext_buffer)
