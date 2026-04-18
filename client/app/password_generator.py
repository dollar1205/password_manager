from __future__ import annotations

from dataclasses import dataclass
import secrets

from .config import DEFAULT_GENERATED_PASSWORD_LENGTH

LOWERCASE = "abcdefghijkmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ"
DIGITS = "23456789"
SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"


@dataclass(slots=True)
class PasswordPolicy:
    length: int = DEFAULT_GENERATED_PASSWORD_LENGTH
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True


def generate_password(policy: PasswordPolicy | None = None) -> str:
    policy = policy or PasswordPolicy()

    pools = []
    if policy.use_lowercase:
        pools.append(LOWERCASE)
    if policy.use_uppercase:
        pools.append(UPPERCASE)
    if policy.use_digits:
        pools.append(DIGITS)
    if policy.use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character group must be enabled.")
    if policy.length < len(pools):
        raise ValueError("Password length is too short for the selected policy.")

    random_source = secrets.SystemRandom()
    password_chars = [random_source.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    password_chars.extend(random_source.choice(alphabet) for _ in range(policy.length - len(password_chars)))
    random_source.shuffle(password_chars)
    return "".join(password_chars)
