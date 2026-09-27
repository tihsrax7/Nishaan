"""
OWNER: Person A/F (auth)
Login + roles.
  - Passwords are hashed with scrypt (salted) -- never stored in plain text.
  - Login returns a signed JWT (HS256) carrying username, officer id, role.
  - 5 wrong passwords in a row locks that account for 60 seconds.
  - Two roles:
      admin   -- the Distribution Officer: shares documents to chosen recipients,
                 traces leaks, controls nodes, reads the audit log.
      officer -- can only open documents that were shared to them.
  - Every user gets their own ML-DSA-65 signing key and ML-KEM-768 key pair at
    first start (kept in the database -- this stands in for the key that would
    live on each officer's own device/smart-card in a real deployment).
"""
import os
import time
import jwt

from . import crypto, db

SECRET = os.environ.get("NISHAAN_JWT_SECRET", "nishaan-demo-secret-change-me")
ALGO = "HS256"
TOKEN_TTL = 60 * 60 * 8
MAX_FAILS, LOCK_SECONDS = 5, 60

# username -> (demo password, officer id, display name, role)
SEED_USERS = {
    "admin":     ("admin123",     1,  "Cdr. Mehta", "admin"),
    "rao":       ("rao123",       7,  "Lt. Cdr. Rao",   "officer"),
    "iyer":      ("iyer123",      11, "Cdr. Iyer",      "officer"),
    "sharma":    ("sharma123",    14, "Lt. Sharma",     "officer"),
    "fernandes": ("fernandes123", 19, "Cdr. Fernandes", "officer"),
    "bose":      ("bose123",      23, "Lt. Cdr. Bose",  "officer"),
}

_fails: dict[str, list] = {}   # username -> [count, locked_until]


def seed_users():
    if db.count_users():
        return
    for u, (pw, oid, name, role) in SEED_USERS.items():
        salt, h = crypto.hash_password(pw)
        dpub, dsk = crypto.new_sig_keypair()
        kpub, ksk = crypto.new_kem_keypair()
        db.add_user(u, salt, h, oid, name, role, dpub, dsk, kpub, ksk)


def login(username: str, password: str):
    """Returns (token, None) on success or (None, reason)."""
    username = (username or "").strip().lower()
    cnt, until = _fails.get(username, [0, 0])
    if until > time.time():
        return None, f"account locked for {int(until - time.time()) + 1}s after too many wrong passwords"
    row = db.get_user(username)
    if not row or not crypto.check_password(password or "", row["pw_salt"], row["pw_hash"]):
        cnt += 1
        _fails[username] = [0, time.time() + LOCK_SECONDS] if cnt >= MAX_FAILS else [cnt, 0]
        return None, "wrong username or password"
    _fails.pop(username, None)
    payload = {"username": username, "officer_id": row["officer_id"], "name": row["name"],
               "role": row["role"], "exp": int(time.time() + TOKEN_TTL)}
    return jwt.encode(payload, SECRET, algorithm=ALGO), None


def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        return None


def roster():
    return [{"username": r["username"], "officer_id": r["officer_id"], "name": r["name"], "role": r["role"],
             "dsa_pub_fingerprint": crypto.sha3(r["dsa_pub"])[:16],
             "kem_pub_fingerprint": crypto.sha3(r["kem_pub"])[:16]}
            for r in db.list_users()]


def reset_lockouts():
    _fails.clear()
