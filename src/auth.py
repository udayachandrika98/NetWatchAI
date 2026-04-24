"""Password handling.

Resolution order, highest precedence first:
    1. NETWATCHAI_PASSWORD environment variable (for Docker / server deploys)
    2. User-chosen password stored in data/.password (set via the UI on first run)
    3. If neither exists, the app shows a "Create your password" screen.

Passwords are stored as a PBKDF2-SHA256 hash, not plaintext.
"""
import hashlib
import hmac
import os
import secrets
import stat

from src.utils import DATA_DIR

PASSWORD_FILE = os.path.join(DATA_DIR, ".password")
_PBKDF2_ITERS = 200_000
_SALT_BYTES = 16


def _hash(plaintext: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, _PBKDF2_ITERS)


def _write_record(plaintext: str) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _hash(plaintext, salt)
    with open(PASSWORD_FILE, "wb") as f:
        f.write(salt + digest)
    try:
        os.chmod(PASSWORD_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _read_record() -> tuple[bytes, bytes] | None:
    if not os.path.exists(PASSWORD_FILE):
        return None
    with open(PASSWORD_FILE, "rb") as f:
        data = f.read()
    # Legacy plaintext file from earlier versions — migrate transparently.
    if len(data) != _SALT_BYTES + 32:
        legacy_plaintext = data.decode(errors="ignore").strip()
        if legacy_plaintext:
            _write_record(legacy_plaintext)
            return _read_record()
        return None
    return data[:_SALT_BYTES], data[_SALT_BYTES:]


def is_setup() -> bool:
    """True if a password is configured (via env var or stored file)."""
    if os.environ.get("NETWATCHAI_PASSWORD"):
        return True
    return _read_record() is not None


def set_password(plaintext: str) -> None:
    """Set or replace the stored password."""
    if not plaintext or len(plaintext) < 6:
        raise ValueError("Password must be at least 6 characters.")
    _write_record(plaintext)


def verify(password: str) -> bool:
    if not password:
        return False
    env_pw = os.environ.get("NETWATCHAI_PASSWORD")
    if env_pw:
        return hmac.compare_digest(password, env_pw)
    record = _read_record()
    if record is None:
        return False
    salt, expected = record
    return hmac.compare_digest(_hash(password, salt), expected)


def reset() -> None:
    """Delete the stored password. Next launch will show 'Create password'."""
    if os.path.exists(PASSWORD_FILE):
        os.remove(PASSWORD_FILE)


# ─────────────────────────────────────────────────────────────
# Legacy helpers kept for backwards compatibility with existing code.
# ─────────────────────────────────────────────────────────────

def get_or_create_password() -> str:
    """Deprecated. Returns env-var password if set, else empty string.
    Use verify()/is_setup()/set_password() instead."""
    return os.environ.get("NETWATCHAI_PASSWORD", "")


def rotate_password() -> str:
    """Generate and store a new random password. Returns plaintext (display once)."""
    pw = secrets.token_urlsafe(9)
    _write_record(pw)
    return pw
