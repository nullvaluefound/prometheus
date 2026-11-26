"""Forge operator accounts: scrypt password hashes, one-time setup codes and signed session cookies.

Host-only. The store lives in the operator state directory, never in an Apprentice image.
"""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import tempfile

from . import policy, runtime

USERNAME = r"[a-z][a-z0-9_.-]{1,31}"
MIN_PASSWORD = 12
MAX_PASSWORD_BYTES = 72
SESSION_HOURS = 12
SETUP_HOURS = 24
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
SCRYPT_MAXMEM = 64 * 1024 * 1024


class AccountError(ValueError):
    """A refusal that is safe to show the person signing in."""


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def folder(state):
    return state / "forge"


def store_path(state):
    return folder(state) / "accounts.json"


def write_private(path, data):
    """Atomically replace path with data, readable only by the service account."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")  # mkstemp creates mode 0600
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def load(state):
    path = store_path(state)
    if not path.exists():
        return {"accounts": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
        raise runtime.RuntimeFailure("Forge account store is invalid")
    return data


def save(state, data):
    write_private(store_path(state), (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("ascii"))


def session_key(state):
    """Return the 32-byte cookie signing key, creating it once with mode 0600."""
    path = folder(state) / "session.key"
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        folder(state).mkdir(mode=0o700, parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            return session_key(state)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
    if len(key) != 32:
        raise runtime.RuntimeFailure("Forge session key is invalid")
    return key


def valid_username(name):
    return isinstance(name, str) and policy.match(name, USERNAME)


def check_password(password, username):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AccountError(f"Use at least {MIN_PASSWORD} characters.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise AccountError(f"Use at most {MAX_PASSWORD_BYTES} bytes.")
    if password.casefold() == username.casefold():
        raise AccountError("The password must differ from the username.")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, maxmem=SCRYPT_MAXMEM, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${b64(salt)}${b64(digest)}"


# Spend the same scrypt work on unknown usernames so timing does not reveal which accounts exist.
DUMMY_HASH = None


def verify_password(stored, password):
    global DUMMY_HASH
    if not isinstance(stored, str):
        DUMMY_HASH = DUMMY_HASH or hash_password(secrets.token_urlsafe(16))
        stored, matched = DUMMY_HASH, False
    else:
        matched = True
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=unb64(salt), n=int(n), r=int(r), p=int(p),
                                dklen=32, maxmem=SCRYPT_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, unb64(expected)) and matched


def code_digest(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def issue_setup(state, username, now=None):
    """Create or reset an account. The password is cleared and every session ends.

    Returns the one-time setup code. Only its SHA-256 is stored."""
    if not valid_username(username):
        raise AccountError("Usernames are 2-32 characters: lowercase letters, digits, dot, dash or underscore.")
    now = now or utcnow()
    code = secrets.token_urlsafe(18)
    with runtime.operator_lock(folder(state)):
        data = load(state)
        account = data["accounts"].get(username, {"created_utc": now.isoformat(), "epoch": 0})
        account.update(password=None, epoch=int(account.get("epoch", 0)) + 1, setup={
            "sha256": code_digest(code), "expires_utc": (now + dt.timedelta(hours=SETUP_HOURS)).isoformat()})
        data["accounts"][username] = account
        save(state, data)
    return code


def complete_setup(state, username, code, password, now=None):
    now = now or utcnow()
    with runtime.operator_lock(folder(state)):
        data = load(state)
        account = data["accounts"].get(username) if valid_username(username) else None
        setup = account.get("setup") if account else None
        if (not isinstance(setup, dict) or not isinstance(code, str) or
                not hmac.compare_digest(code_digest(code), str(setup.get("sha256", ""))) or
                now >= dt.datetime.fromisoformat(setup["expires_utc"])):
            raise AccountError("The username or setup code is not valid, or the code has expired.")
        check_password(password, username)
        account.update(password=hash_password(password), setup=None, changed_utc=now.isoformat())
        save(state, data)
        return account["epoch"]


def authenticate(state, username, password):
    """Return the account's session epoch, or None. Unknown names cost the same work as known ones."""
    account = load(state)["accounts"].get(username) if valid_username(username) else None
    stored = account.get("password") if account else None
    if verify_password(stored, password if isinstance(password, str) else "") and account:
        return account["epoch"]
    return None


def change_password(state, username, current, new, now=None):
    """Replace the password after re-checking the current one. Other sessions end."""
    now = now or utcnow()
    with runtime.operator_lock(folder(state)):
        data = load(state)
        account = data["accounts"].get(username)
        if not account or not verify_password(account.get("password"), current):
            raise AccountError("The current password is not correct.")
        check_password(new, username)
        if verify_password(account["password"], new):
            raise AccountError("Choose a password you have not just used.")
        account.update(password=hash_password(new), epoch=int(account["epoch"]) + 1, changed_utc=now.isoformat())
        save(state, data)
        return account["epoch"]


def end_sessions(state, username):
    with runtime.operator_lock(folder(state)):
        data = load(state)
        if username in data["accounts"]:
            data["accounts"][username]["epoch"] = int(data["accounts"][username]["epoch"]) + 1
            save(state, data)


def remove(state, username):
    with runtime.operator_lock(folder(state)):
        data = load(state)
        if data["accounts"].pop(username, None) is None:
            raise AccountError("No such account.")
        save(state, data)


def listing(state):
    rows = []
    for name, account in sorted(load(state)["accounts"].items()):
        setup = account.get("setup")
        rows.append({"user": name, "password_set": bool(account.get("password")),
                     "setup_expires_utc": setup.get("expires_utc") if isinstance(setup, dict) else None,
                     "changed_utc": account.get("changed_utc")})
    return rows


def issue_session(state, username, epoch, now=None):
    now = now or utcnow()
    expires = int((now + dt.timedelta(hours=SESSION_HOURS)).timestamp())
    body = b64(json.dumps({"u": username, "e": epoch, "x": expires}, separators=(",", ":")).encode("ascii"))
    mac = hmac.new(session_key(state), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{b64(mac)}"


def session_user(state, token, now=None):
    """Return the username for a valid, unexpired, unrevoked session token, otherwise None."""
    now = now or utcnow()
    try:
        body, mac = token.split(".")
        expected = hmac.new(session_key(state), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, unb64(mac)):
            return None
        claims = json.loads(unb64(body))
        username, epoch, expires = claims["u"], claims["e"], claims["x"]
        if not isinstance(expires, int) or now.timestamp() >= expires:
            return None
        account = load(state)["accounts"].get(username) if valid_username(username) else None
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None
    if not account or not account.get("password") or account.get("epoch") != epoch:
        return None
    return username
