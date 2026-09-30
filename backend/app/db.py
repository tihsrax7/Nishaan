"""
OWNER: Person A or B
SQLite persistence for everything -- users + their (sealed) keys, ledger node keys, documents,
recipients, key-shares, ledger blocks, leak-investigation cases and the audit log. Surviving a
server restart matters: node and officer signing keys live here, so old ledger blocks can still
be verified after a restart.

Tables:
  users(username, pw_salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk,
        active, created_at, key_salt, keys_sealed)       -- private keys sealed under the password
  nodes(name, dsa_pub, dsa_sk, online, sealed)          -- node key sealed under its key file
  documents(doc_id, title, filename, doctype, pages, classification, nonce, ct_path,
            orig_path, ct_hash, created_by, created_at, expires_at, revoked, revoked_at,
            visible_mark)                               -- visible_mark 0 = copies look identical
  recipients(doc_id, username, revoked_at)               -- revoked_at set = access withdrawn
  shares(doc_id, node_name, idx, half1, half2)          -- one sealed Shamir share per node per doc
  blocks(idx, session, doc_id, officer_id, username, block_json, original_json)
  cases(case_id, ...)                                   -- leak investigations (two-person rule)
  sys_keys(name, pub, sk)                               -- evidence-signing authority key (sealed)
  events(id, time, kind, username, doc_id, detail, prev_hash, hash)
                                                        -- audit log, itself hash-chained
"""
import sqlite3
import json
import os
import time
import hashlib
import threading

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("NISHAAN_DB", os.path.join(BASE, "nishaan.db"))
GENESIS = "00" * 32
_ev_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, pw_salt BLOB, pw_hash BLOB, officer_id INTEGER UNIQUE,
    name TEXT, role TEXT, dsa_pub BLOB, dsa_sk BLOB, kem_pub BLOB, kem_sk BLOB,
    active INTEGER NOT NULL DEFAULT 1, created_at REAL, key_salt BLOB, keys_sealed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nodes (
    name TEXT PRIMARY KEY, dsa_pub BLOB, dsa_sk BLOB, online INTEGER, sealed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY, title TEXT, filename TEXT, doctype TEXT, pages INTEGER,
    classification TEXT, nonce BLOB, ct_path TEXT, orig_path TEXT, ct_hash TEXT,
    created_by TEXT, created_at REAL, expires_at REAL, revoked INTEGER NOT NULL DEFAULT 0, revoked_at REAL,
    visible_mark INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recipients (
    doc_id TEXT, username TEXT, revoked_at REAL, PRIMARY KEY (doc_id, username)
);
CREATE TABLE IF NOT EXISTS shares (
    doc_id TEXT, node_name TEXT, idx INTEGER, half1 BLOB, half2 BLOB,
    PRIMARY KEY (doc_id, node_name)
);
CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY, session TEXT UNIQUE, doc_id TEXT, officer_id INTEGER,
    username TEXT, block_json TEXT, original_json TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY, doc_id TEXT, officer_id INTEGER, username TEXT,
    leaked_name TEXT, leaked_size INTEGER, leaked_sha256 TEXT, leaked_sha3 TEXT,
    result_json TEXT, status TEXT, requested_by TEXT, requested_at REAL,
    decided_by TEXT, decided_at REAL, decision_note TEXT
);
CREATE TABLE IF NOT EXISTS sys_keys (
    name TEXT PRIMARY KEY, pub BLOB, sk BLOB
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time REAL, kind TEXT, username TEXT,
    doc_id TEXT, detail TEXT, prev_hash TEXT, hash TEXT
);
"""

# columns added after v4 -- older databases are upgraded in place
_UPGRADES = {
    "users": [("active", "INTEGER NOT NULL DEFAULT 1"), ("created_at", "REAL"), ("key_salt", "BLOB"),
              ("keys_sealed", "INTEGER NOT NULL DEFAULT 0")],
    "nodes": [("sealed", "INTEGER NOT NULL DEFAULT 0")],
    "documents": [("expires_at", "REAL"), ("revoked", "INTEGER NOT NULL DEFAULT 0"), ("revoked_at", "REAL"),
                  ("visible_mark", "INTEGER NOT NULL DEFAULT 0")],
    "recipients": [("revoked_at", "REAL")],
    "events": [("prev_hash", "TEXT"), ("hash", "TEXT")],
}


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    for table, cols in _UPGRADES.items():
        have = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        for col, decl in cols:
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    conn.commit()
    conn.close()
    _chain_old_events()


def wipe():
    """Demo reset: drop every table and recreate empty."""
    conn = get_conn()
    for t in ["users", "nodes", "documents", "recipients", "shares", "blocks", "cases", "sys_keys", "events"]:
        conn.execute(f"DROP TABLE IF EXISTS {t}")
    conn.commit()
    conn.close()
    init_db()


def _one(sql, args=()):
    conn = get_conn()
    row = conn.execute(sql, args).fetchone()
    conn.close()
    return row


def _all(sql, args=()):
    conn = get_conn()
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return rows


def _exec(sql, args=()):
    conn = get_conn()
    conn.execute(sql, args)
    conn.commit()
    conn.close()


def _execmany(sql, rows):
    conn = get_conn()
    conn.executemany(sql, rows)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- users
def count_users():
    return _one("SELECT COUNT(*) AS c FROM users")["c"]


def add_user(username, salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk,
             key_salt=None, keys_sealed=0):
    _exec("INSERT INTO users (username, pw_salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk, "
          "active, created_at, key_salt, keys_sealed) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?,?)",
          (username, salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk, time.time(),
           key_salt, int(keys_sealed)))


def set_user_keys_sealed(username, key_salt, dsa_sk, kem_sk):
    _exec("UPDATE users SET key_salt=?, dsa_sk=?, kem_sk=?, keys_sealed=1 WHERE username=?",
          (key_salt, dsa_sk, kem_sk, username))


def set_user_active(username, active):
    _exec("UPDATE users SET active=? WHERE username=?", (int(active), username))


def next_officer_id():
    row = _one("SELECT MAX(officer_id) AS m FROM users WHERE role='officer'")
    nxt = max(11, (row["m"] or 0) + 1)
    while _one("SELECT 1 FROM users WHERE officer_id=?", (nxt,)):
        nxt += 1
    return nxt


def get_user(username):
    return _one("SELECT * FROM users WHERE username=?", (username,))


def get_user_by_officer(officer_id):
    return _one("SELECT * FROM users WHERE officer_id=?", (officer_id,))


def list_users():
    return _all("SELECT username, officer_id, name, role, dsa_pub, kem_pub, active, created_at, keys_sealed "
                "FROM users ORDER BY officer_id")


def list_unsealed_users():
    return _all("SELECT username FROM users WHERE keys_sealed=0")


# ---------------------------------------------------------------- nodes
def count_nodes():
    return _one("SELECT COUNT(*) AS c FROM nodes")["c"]


def add_node(name, pub, sk, online, sealed=1):
    _exec("INSERT INTO nodes (name, dsa_pub, dsa_sk, online, sealed) VALUES (?,?,?,?,?)",
          (name, pub, sk, int(online), int(sealed)))


def list_nodes():
    return _all("SELECT * FROM nodes ORDER BY name")


def set_node_online(name, online):
    _exec("UPDATE nodes SET online=? WHERE name=?", (int(online), name))


def set_node_sk_sealed(name, sealed_sk):
    _exec("UPDATE nodes SET dsa_sk=?, sealed=1 WHERE name=?", (sealed_sk, name))


# ---------------------------------------------------------------- documents
def save_document(doc_id, title, filename, doctype, pages, classification, nonce,
                  ct_path, orig_path, ct_hash, created_by, recipients, expires_at=None, visible_mark=False):
    conn = get_conn()
    conn.execute("INSERT INTO documents (doc_id, title, filename, doctype, pages, classification, nonce, ct_path, "
                 "orig_path, ct_hash, created_by, created_at, expires_at, revoked, visible_mark) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                 (doc_id, title, filename, doctype, pages, classification, nonce,
                  ct_path, orig_path, ct_hash, created_by, time.time(), expires_at, 1 if visible_mark else 0))
    conn.executemany("INSERT INTO recipients (doc_id, username) VALUES (?,?)", [(doc_id, u) for u in recipients])
    conn.commit()
    conn.close()


def get_document(doc_id):
    return _one("SELECT * FROM documents WHERE doc_id=?", (doc_id,))


def list_documents(for_user=None):
    if for_user:
        return _all("SELECT d.* FROM documents d JOIN recipients r ON r.doc_id=d.doc_id "
                    "WHERE r.username=? AND r.revoked_at IS NULL ORDER BY d.created_at DESC", (for_user,))
    return _all("SELECT * FROM documents ORDER BY created_at DESC")


def get_recipients(doc_id):
    """Recipients who currently have access."""
    return [r["username"] for r in _all("SELECT username FROM recipients WHERE doc_id=? AND revoked_at IS NULL", (doc_id,))]


def get_revoked_recipients(doc_id):
    return [r["username"] for r in _all("SELECT username FROM recipients WHERE doc_id=? AND revoked_at IS NOT NULL", (doc_id,))]


def is_recipient(doc_id, username):
    """Currently allowed to open."""
    return _one("SELECT 1 FROM recipients WHERE doc_id=? AND username=? AND revoked_at IS NULL",
                (doc_id, username)) is not None


def was_recipient(doc_id, username):
    """Was ever given this document (even if access was later revoked)."""
    return _one("SELECT 1 FROM recipients WHERE doc_id=? AND username=?", (doc_id, username)) is not None


def set_recipient_access(doc_id, username, allow):
    _exec("UPDATE recipients SET revoked_at=? WHERE doc_id=? AND username=?",
          (None if allow else time.time(), doc_id, username))


def set_document_revoked(doc_id, revoked):
    _exec("UPDATE documents SET revoked=?, revoked_at=? WHERE doc_id=?",
          (int(revoked), time.time() if revoked else None, doc_id))


# ---------------------------------------------------------------- key shares
def save_shares(rows):
    """rows: list of (doc_id, node_name, idx, half1, half2) -- halves already sealed"""
    _execmany("INSERT INTO shares (doc_id, node_name, idx, half1, half2) VALUES (?,?,?,?,?)", rows)


def get_shares(doc_id, node_names):
    q = ",".join("?" * len(node_names))
    return _all(f"SELECT * FROM shares WHERE doc_id=? AND node_name IN ({q})", (doc_id, *node_names))


def list_all_shares():
    return _all("SELECT * FROM shares")


def update_share(doc_id, node_name, half1, half2):
    _exec("UPDATE shares SET half1=?, half2=? WHERE doc_id=? AND node_name=?", (half1, half2, doc_id, node_name))


# ---------------------------------------------------------------- ledger blocks
def last_block():
    return _one("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1")


def save_block(block: dict):
    js = json.dumps(block, sort_keys=True)
    _exec("INSERT INTO blocks VALUES (?,?,?,?,?,?,?)",
          (block["index"], block["session"], block["doc_id"], block["officer_id"],
           block["username"], js, js))


def list_blocks(asc=True):
    return _all("SELECT * FROM blocks ORDER BY idx " + ("ASC" if asc else "DESC"))


def get_block(idx):
    return _one("SELECT * FROM blocks WHERE idx=?", (idx,))


def overwrite_block_json(idx, js):
    _exec("UPDATE blocks SET block_json=? WHERE idx=?", (js, idx))


def restore_all_blocks():
    _exec("UPDATE blocks SET block_json=original_json")


def delete_block(idx):
    """Demo only: an insider deleting a record straight from the main database."""
    _exec("DELETE FROM blocks WHERE idx=?", (idx,))


def upsert_block_json(js: str):
    """Write a block (as agreed by the node copies) back into the main ledger."""
    b = json.loads(js)
    _exec("INSERT OR REPLACE INTO blocks VALUES (?,?,?,?,?,?,?)",
          (b["index"], b["session"], b["doc_id"], b["officer_id"], b["username"], js, js))


def find_blocks(doc_id, officer_id=None):
    if officer_id is None:
        return _all("SELECT * FROM blocks WHERE doc_id=? ORDER BY idx", (doc_id,))
    return _all("SELECT * FROM blocks WHERE doc_id=? AND officer_id=? ORDER BY idx", (doc_id, officer_id))


def count_opens(doc_id):
    return _one("SELECT COUNT(*) AS c FROM blocks WHERE doc_id=?", (doc_id,))["c"]


# ---------------------------------------------------------------- cases (leak investigations)
def next_case_id():
    row = _one("SELECT COUNT(*) AS c FROM cases")
    return f"C-{row['c'] + 1:04d}"


def save_case(case: dict):
    _exec("INSERT INTO cases (case_id, doc_id, officer_id, username, leaked_name, leaked_size, leaked_sha256, "
          "leaked_sha3, result_json, status, requested_by, requested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
          (case["case_id"], case["doc_id"], case["officer_id"], case["username"], case["leaked_name"],
           case["leaked_size"], case["leaked_sha256"], case["leaked_sha3"], json.dumps(case["result"]),
           "PENDING", case["requested_by"], time.time()))


def get_case(case_id):
    return _one("SELECT * FROM cases WHERE case_id=?", (case_id,))


def list_cases():
    return _all("SELECT * FROM cases ORDER BY requested_at DESC")


def decide_case(case_id, status, username, note):
    _exec("UPDATE cases SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE case_id=? AND status='PENDING'",
          (status, username, time.time(), note, case_id))


# ---------------------------------------------------------------- system keys
def get_sys_key(name):
    return _one("SELECT * FROM sys_keys WHERE name=?", (name,))


def add_sys_key(name, pub, sk):
    _exec("INSERT INTO sys_keys (name, pub, sk) VALUES (?,?,?)", (name, pub, sk))


# ---------------------------------------------------------------- audit events (hash-chained)
def _event_hash(prev, t, kind, username, doc_id, detail):
    payload = json.dumps([prev, round(t, 6), kind, username, doc_id, detail], separators=(",", ":"))
    return hashlib.sha3_256(payload.encode()).hexdigest()


def log_event(kind, username=None, doc_id=None, detail=""):
    with _ev_lock:
        conn = get_conn()
        last = conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        prev = (last["hash"] if last and last["hash"] else GENESIS)
        t = round(time.time(), 6)
        h = _event_hash(prev, t, kind, username, doc_id, detail)
        conn.execute("INSERT INTO events (time, kind, username, doc_id, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                     (t, kind, username, doc_id, detail, prev, h))
        conn.commit()
        conn.close()


def _chain_old_events():
    """Give events written by older versions (no hash yet) their place in the chain."""
    with _ev_lock:
        conn = get_conn()
        rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        if rows and any(r["hash"] is None for r in rows):
            prev = GENESIS
            for r in rows:
                h = _event_hash(prev, r["time"], r["kind"], r["username"], r["doc_id"], r["detail"])
                conn.execute("UPDATE events SET prev_hash=?, hash=? WHERE id=?", (prev, h, r["id"]))
                prev = h
            conn.commit()
        conn.close()


def verify_events():
    """Re-check the audit log's own hash chain. Returns (ok, checked, first_bad_id)."""
    prev = GENESIS
    rows = _all("SELECT * FROM events ORDER BY id")
    for r in rows:
        if r["prev_hash"] != prev or _event_hash(prev, r["time"], r["kind"], r["username"], r["doc_id"], r["detail"]) != r["hash"]:
            return False, len(rows), r["id"]
        prev = r["hash"]
    return True, len(rows), None


def list_events(limit=300):
    return _all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))


def all_events_since(t0):
    return _all("SELECT * FROM events WHERE time>=? ORDER BY id", (t0,))
