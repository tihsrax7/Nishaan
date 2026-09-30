"""
OWNER: Person A/F (auth)
Login + roles.
  - Passwords are hashed with scrypt (salted) -- never stored in plain text.
  - Login returns a signed JWT (HS256) carrying username, officer id, role.
  - 5 wrong passwords in a row locks that account for 60 seconds.
  - Three roles:
      admin    -- the Distribution Officer: shares documents to chosen recipients,
                  traces leaks, controls nodes, manages people.
      security -- the Security Officer: traces leaks, CONFIRMS or rejects leak findings
                  (two-person rule), watches insider alerts, reads the audit log.
      officer  -- can only open documents that were shared to them.
  - Every user gets their own ML-DSA-65 signing key and ML-KEM-768 key pair. The private
    halves are stored SEALED (AES-256-GCM) under a key derived from that user's own password,
    so the server cannot sign "I opened this" on an officer's behalf: the officer must type
    their password at the moment of opening. (In deployment the keys live on a smart card.)
"""
import os
import re
import time
import secrets
import jwt

from . import crypto, db

def _load_secret() -> bytes:
    """Token-signing secret. NEVER hard-coded: taken from NISHAAN_JWT_SECRET if set,
    otherwise a random 64-byte secret is generated on first start and kept in
    backend/.jwt_secret (owner-only permissions, git-ignored)."""
    env = os.environ.get("NISHAAN_JWT_SECRET")
    if env:
        if len(env) < 32:
            raise RuntimeError("NISHAAN_JWT_SECRET must be at least 32 characters")
        return env.encode()
    path = os.environ.get("NISHAAN_SECRET_FILE",
                          os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".jwt_secret"))
    if os.path.exists(path):
        with open(path, "rb") as f:
            val = f.read().strip()
        if len(val) >= 32:
            return val
    val = secrets.token_hex(64).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(val)
    return val


SECRET = _load_secret()
ALGO = "HS256"
TOKEN_TTL = 60 * 60 * 8
MAX_FAILS, LOCK_SECONDS = 5, 60

# username -> (demo password, officer id, display name, role). Admin is #00 and is never watermarked.
SEED_USERS = {"admin": ("admin123", 0, "Administrator", "admin"),
              "security": ("security123", 99, "Security Officer", "security")}
STAFF_ROLES = ("admin", "security")
for _i in range(1, 11):                                   # officer1 .. officer10
    SEED_USERS[f"officer{_i}"] = (f"officer{_i}123", _i, f"Officer {_i}", "officer")

_fails: dict[str, list] = {}   # username -> [count, locked_until]
_DUMMY = crypto.hash_password(secrets.token_hex(16))


def _sealed_keys(username: str, password: str):
    """New key pairs, private halves sealed under the password. Returns db fields."""
    dpub, dsk = crypto.new_sig_keypair()
    kpub, ksk = crypto.new_kem_keypair()
    ks = secrets.token_bytes(16)
    kek = crypto.derive_kek(password, ks)
    return (dpub, crypto.seal(kek, dsk, f"{username}:dsa"), kpub, crypto.seal(kek, ksk, f"{username}:kem"), ks)


def seed_users():
    if not db.count_users():
        for u, (pw, oid, name, role) in SEED_USERS.items():
            salt, h = crypto.hash_password(pw)
            dpub, dsk, kpub, ksk, ks = _sealed_keys(u, pw)
            db.add_user(u, salt, h, oid, name, role, dpub, dsk, kpub, ksk, ks, 1)
        return
    # upgrading a v4 database: add the Security Officer if missing
    if not db.get_user("security") and not db.get_user_by_officer(99):
        pw, oid, name, role = SEED_USERS["security"]
        salt, h = crypto.hash_password(pw)
        dpub, dsk, kpub, ksk, ks = _sealed_keys("security", pw)
        db.add_user("security", salt, h, oid, name, role, dpub, dsk, kpub, ksk, ks, 1)


def _seal_existing(row, password: str):
    """v4 databases stored private keys unsealed: seal them the first time the user signs in."""
    ks = secrets.token_bytes(16)
    kek = crypto.derive_kek(password, ks)
    db.set_user_keys_sealed(row["username"], ks, crypto.seal(kek, row["dsa_sk"], f"{row['username']}:dsa"),
                            crypto.seal(kek, row["kem_sk"], f"{row['username']}:kem"))


def seal_seed_accounts():
    """On upgrade, seal the demo accounts' keys straight away (their demo passwords are known),
    so no private key is left in the database unsealed."""
    for r in db.list_unsealed_users():
        if r["username"] in SEED_USERS:
            _seal_existing(db.get_user(r["username"]), SEED_USERS[r["username"]][0])


def unlock_keys(username: str, password: str):
    """Step-up authentication for 'sign to open': checks the password again (same lockout as login)
    and unseals the officer's private keys for this one operation. Returns (dsa_sk, kem_sk) or (None, reason)."""
    username = (username or "").strip().lower()
    cnt, until = _fails.get(username, [0, 0])
    if until > time.time():
        return None, f"account locked for {int(until - time.time()) + 1}s after too many wrong passwords"
    row = db.get_user(username)
    if not row or not crypto.check_password(password or "", row["pw_salt"], row["pw_hash"]):
        cnt += 1
        _fails[username] = [0, time.time() + LOCK_SECONDS] if cnt >= MAX_FAILS else [cnt, 0]
        return None, "wrong password -- the document was not opened"
    _fails.pop(username, None)
    if not row["keys_sealed"]:
        _seal_existing(row, password)
        row = db.get_user(username)
    kek = crypto.derive_kek(password, row["key_salt"])
    try:
        return (crypto.unseal(kek, row["dsa_sk"], f"{username}:dsa"), crypto.unseal(kek, row["kem_sk"], f"{username}:kem")), None
    except Exception:
        return None, "your private keys could not be unlocked"


def login(username: str, password: str):
    """Returns (token, None) on success or (None, reason)."""
    username = (username or "").strip().lower()
    cnt, until = _fails.get(username, [0, 0])
    if until > time.time():
        return None, f"account locked for {int(until - time.time()) + 1}s after too many wrong passwords"
    row = db.get_user(username)
    # always run the (slow) password hash, even for unknown users, so response time
    # does not reveal which usernames exist
    pw_ok = crypto.check_password(password or "", row["pw_salt"] if row else _DUMMY[0], row["pw_hash"] if row else _DUMMY[1])
    if row and not row["active"] and pw_ok:
        return None, "this account has been deactivated by the Distribution Officer"
    if not row or not pw_ok:
        cnt += 1
        _fails[username] = [0, time.time() + LOCK_SECONDS] if cnt >= MAX_FAILS else [cnt, 0]
        return None, "wrong username or password"
    _fails.pop(username, None)
    if not row["keys_sealed"]:
        _seal_existing(row, password)
    now = int(time.time())
    payload = {"sub": username, "username": username, "officer_id": row["officer_id"], "name": row["name"],
               "role": row["role"], "iat": now, "exp": now + TOKEN_TTL, "jti": secrets.token_hex(8)}
    return jwt.encode(payload, SECRET, algorithm=ALGO), None


def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO], options={"require": ["exp", "iat", "sub"]})
    except jwt.PyJWTError:
        return None


USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")


def create_user(username: str, name: str, password: str, officer_id: int | None = None, role: str = "officer"):
    """Admin-only: add a new person. Returns (row, None) or (None, reason).
    Every new user is issued their own ML-DSA-65 signing key and ML-KEM-768 key pair."""
    username = (username or "").strip().lower()
    name = " ".join((name or "").split())
    if not USERNAME_RE.match(username):
        return None, "username must be 3-32 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter"
    if db.get_user(username):
        return None, f"the username '{username}' is already taken"
    if not (2 <= len(name) <= 60):
        return None, "enter the person's full name with rank (2-60 characters)"
    if len(password or "") < 6:
        return None, "the password must be at least 6 characters"
    if officer_id is None:
        officer_id = db.next_officer_id()
    if not (1 <= officer_id <= 65535):
        return None, "the officer number must be between 1 and 65535"
    if db.get_user_by_officer(officer_id):
        return None, f"officer number #{officer_id:02d} is already in use"
    salt, h = crypto.hash_password(password)
    dpub, dsk, kpub, ksk, ks = _sealed_keys(username, password)
    db.add_user(username, salt, h, officer_id, name, role, dpub, dsk, kpub, ksk, ks, 1)
    return db.get_user(username), None


def roster():
    return [{"username": r["username"], "officer_id": r["officer_id"], "name": r["name"], "role": r["role"],
             "active": bool(r["active"]), "created_at": r["created_at"], "keys_sealed": bool(r["keys_sealed"]),
             "dsa_pub_fingerprint": crypto.sha3(r["dsa_pub"])[:16],
             "kem_pub_fingerprint": crypto.sha3(r["kem_pub"])[:16]}
            for r in db.list_users()]


def reset_lockouts():
    _fails.clear()
