"""
OWNER: Person A or B
SQLite persistence for everything -- users + their keys, ledger node keys, documents,
recipients, key-shares, ledger blocks, and the audit log. Surviving a server restart
matters: node and officer signing keys live here, so old ledger blocks can still be
verified after a restart.

Tables:
  users(username, pw_salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk)
  nodes(name, dsa_pub, dsa_sk, online)
  documents(doc_id, title, filename, doctype, pages, classification, nonce, ct_path,
            orig_path, ct_hash, created_by, created_at)
  recipients(doc_id, username)
  shares(doc_id, node_name, idx, half1, half2)       -- one Shamir share per node per doc
  blocks(idx, session, doc_id, officer_id, username, block_json, original_json)
  events(id, time, kind, username, doc_id, detail)   -- audit log incl. DENIED attempts
"""
import sqlite3
import json
import os
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("NISHAAN_DB", os.path.join(BASE, "nishaan.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, pw_salt BLOB, pw_hash BLOB, officer_id INTEGER UNIQUE,
    name TEXT, role TEXT, dsa_pub BLOB, dsa_sk BLOB, kem_pub BLOB, kem_sk BLOB
);
CREATE TABLE IF NOT EXISTS nodes (
    name TEXT PRIMARY KEY, dsa_pub BLOB, dsa_sk BLOB, online INTEGER
);
CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY, title TEXT, filename TEXT, doctype TEXT, pages INTEGER,
    classification TEXT, nonce BLOB, ct_path TEXT, orig_path TEXT, ct_hash TEXT,
    created_by TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS recipients (
    doc_id TEXT, username TEXT, PRIMARY KEY (doc_id, username)
);
CREATE TABLE IF NOT EXISTS shares (
    doc_id TEXT, node_name TEXT, idx INTEGER, half1 BLOB, half2 BLOB,
    PRIMARY KEY (doc_id, node_name)
);
CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY, session TEXT UNIQUE, doc_id TEXT, officer_id INTEGER,
    username TEXT, block_json TEXT, original_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time REAL, kind TEXT, username TEXT,
    doc_id TEXT, detail TEXT
);
"""


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def wipe():
    """Demo reset: drop every table and recreate empty."""
    conn = get_conn()
    for t in ["users", "nodes", "documents", "recipients", "shares", "blocks", "events"]:
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


# ---------------------------------------------------------------- users
def count_users():
    return _one("SELECT COUNT(*) AS c FROM users")["c"]


def add_user(username, salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk):
    _exec("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?)",
          (username, salt, pw_hash, officer_id, name, role, dsa_pub, dsa_sk, kem_pub, kem_sk))


def get_user(username):
    return _one("SELECT * FROM users WHERE username=?", (username,))


def get_user_by_officer(officer_id):
    return _one("SELECT * FROM users WHERE officer_id=?", (officer_id,))


def list_users():
    return _all("SELECT username, officer_id, name, role, dsa_pub, kem_pub FROM users ORDER BY officer_id")


# ---------------------------------------------------------------- nodes
def count_nodes():
    return _one("SELECT COUNT(*) AS c FROM nodes")["c"]


def add_node(name, pub, sk, online):
    _exec("INSERT INTO nodes VALUES (?,?,?,?)", (name, pub, sk, int(online)))


def list_nodes():
    return _all("SELECT * FROM nodes ORDER BY name")


def set_node_online(name, online):
    _exec("UPDATE nodes SET online=? WHERE name=?", (int(online), name))


# ---------------------------------------------------------------- documents
def save_document(doc_id, title, filename, doctype, pages, classification, nonce,
                  ct_path, orig_path, ct_hash, created_by, recipients):
    conn = get_conn()
    conn.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                 (doc_id, title, filename, doctype, pages, classification, nonce,
                  ct_path, orig_path, ct_hash, created_by, time.time()))
    conn.executemany("INSERT INTO recipients VALUES (?,?)", [(doc_id, u) for u in recipients])
    conn.commit()
    conn.close()


def get_document(doc_id):
    return _one("SELECT * FROM documents WHERE doc_id=?", (doc_id,))


def list_documents(for_user=None):
    if for_user:
        return _all("SELECT d.* FROM documents d JOIN recipients r ON r.doc_id=d.doc_id "
                    "WHERE r.username=? ORDER BY d.created_at DESC", (for_user,))
    return _all("SELECT * FROM documents ORDER BY created_at DESC")


def get_recipients(doc_id):
    return [r["username"] for r in _all("SELECT username FROM recipients WHERE doc_id=?", (doc_id,))]


def is_recipient(doc_id, username):
    return _one("SELECT 1 FROM recipients WHERE doc_id=? AND username=?", (doc_id, username)) is not None


# ---------------------------------------------------------------- key shares
def save_shares(rows):
    """rows: list of (doc_id, node_name, idx, half1, half2)"""
    conn = get_conn()
    conn.executemany("INSERT INTO shares VALUES (?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def get_shares(doc_id, node_names):
    q = ",".join("?" * len(node_names))
    return _all(f"SELECT * FROM shares WHERE doc_id=? AND node_name IN ({q})", (doc_id, *node_names))


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


def find_blocks(doc_id, officer_id=None):
    if officer_id is None:
        return _all("SELECT * FROM blocks WHERE doc_id=? ORDER BY idx", (doc_id,))
    return _all("SELECT * FROM blocks WHERE doc_id=? AND officer_id=? ORDER BY idx", (doc_id, officer_id))


def count_opens(doc_id):
    return _one("SELECT COUNT(*) AS c FROM blocks WHERE doc_id=?", (doc_id,))["c"]


# ---------------------------------------------------------------- audit events
def log_event(kind, username=None, doc_id=None, detail=""):
    _exec("INSERT INTO events (time, kind, username, doc_id, detail) VALUES (?,?,?,?,?)",
          (time.time(), kind, username, doc_id, detail))


def list_events(limit=300):
    return _all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
