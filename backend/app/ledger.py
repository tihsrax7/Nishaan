"""
OWNER: Person B (backend/ledger)
5-node permissioned ledger with 4-of-5 quorum. Nodes are simulated in one process
(not 5 separate machines), but every cryptographic step is real and every node key
is persisted, so the chain stays verifiable across restarts.

Open flow:
  1. The officer signs a receipt (doc, who, when, session, ciphertext hash) with
     their own ML-DSA-65 key.
  2. A block is built: index, prev_hash (SHA3 link to the previous block), the
     receipt, its hash, and the officer's signature. block_hash = SHA3-256(block).
  3. Every ONLINE node independently checks the receipt hash + the officer's
     signature AND the access policy (officer still a recipient, document not
     withdrawn, access window still open), and only then signs block_hash with
     its own ML-DSA-65 key (a vote).
  4. >= 4 valid votes -> block accepted and appended; else the file stays locked.

Each node also keeps ITS OWN COPY of the chain in its own store (node_ledgers/N1.db ...).
A node only stores a block after checking its hash and the 4-of-5 node signatures itself.
verify_chain() re-checks everything from scratch -- each hash, each link, each officer
signature, each node vote -- and then compares the main ledger with every node's copy,
so a record that was edited, inserted or DELETED in one place is caught by the others.
restore_from_nodes() rebuilds the main ledger from the node copies.

Session watermark: the invisible mark in each copy is MARK_BASE + the block's index, so a
leaked copy points to the exact ledger record (who, when, which session) -- not only to an
officer. tamper() exists only for the demo.
"""
import json
import os
import sqlite3
import time
import threading

from . import crypto, db, keystore

N_NODES, QUORUM = 5, 4
MARK_BASE = 1024          # marks >= MARK_BASE are session marks (MARK_BASE + block index); smaller = legacy officer marks
MARK_MAX = 0xFFFF         # 16-bit mark -> up to 64,511 openings in this prototype
CORE_FIELDS = ["index", "prev_hash", "doc_id", "username", "officer_id", "session",
               "time", "receipt", "receipt_hash", "officer_sig"]
GENESIS = "00" * 32
_lock = threading.Lock()


def _hash_core(block: dict) -> str:
    core = {k: block[k] for k in CORE_FIELDS}
    return crypto.sha3(json.dumps(core, sort_keys=True).encode())


def receipt_hash(receipt: dict) -> str:
    return crypto.sha3(json.dumps(receipt, sort_keys=True).encode())


# ---------------------------------------------------------------- nodes
def seed_nodes():
    if not db.count_nodes():
        for i in range(N_NODES):
            name = f"N{i + 1}"
            pub, sk = crypto.new_sig_keypair()
            db.add_node(name, pub, crypto.seal(keystore.key(name), sk, f"{name}:dsa"),
                        online=(i + 1 != 5))                      # demo default: N5 offline -> 4/5
    seal_legacy()


def seal_legacy():
    """Upgrade a v4 database: seal node signing keys and every stored key share
    under the per-node key files (a copy of the database alone becomes useless)."""
    for n in db.list_nodes():
        if not n["sealed"]:
            db.set_node_sk_sealed(n["name"], crypto.seal(keystore.key(n["name"]), n["dsa_sk"], f"{n['name']}:dsa"))
    for r in db.list_all_shares():
        if len(r["half1"]) == 16:                                  # plain 16-byte Shamir half = not sealed yet
            h1, h2 = seal_share(r["doc_id"], r["node_name"], r["half1"], r["half2"])
            db.update_share(r["doc_id"], r["node_name"], h1, h2)


def seal_share(doc_id, node_name, half1, half2):
    k = keystore.key(node_name)
    return (crypto.seal(k, half1, f"{node_name}:{doc_id}:1"), crypto.seal(k, half2, f"{node_name}:{doc_id}:2"))


def open_share(row):
    """A node releases its share: unseal with that node's own key file."""
    k = keystore.key(row["node_name"])
    return (row["idx"], crypto.unseal(k, row["half1"], f"{row['node_name']}:{row['doc_id']}:1"),
            crypto.unseal(k, row["half2"], f"{row['node_name']}:{row['doc_id']}:2"))


def _node_sk(n):
    return crypto.unseal(keystore.key(n["name"]), n["dsa_sk"], f"{n['name']}:dsa")


def policy_check(doc_id, username):
    """Each node's own access-policy check before it votes. Returns None if allowed, else the reason."""
    d = db.get_document(doc_id)
    if d is None:
        return "no such document"
    if d["revoked"]:
        return "document withdrawn by the Distribution Officer"
    if d["expires_at"] and time.time() > d["expires_at"]:
        return "access window has closed"
    u = db.get_user(username)
    if not u or not u["active"]:
        return "account deactivated"
    if not db.is_recipient(doc_id, username):
        return "officer is not (or no longer) a recipient"
    return None


def status():
    counts = {n: len(_replica(n)) for n in _node_names()}
    return [{"name": n["name"], "online": bool(n["online"]), "records_held": counts.get(n["name"], 0),
             "key_fingerprint": crypto.sha3(n["dsa_pub"])[:16]} for n in db.list_nodes()]


def mark_for_block(index: int) -> int:
    m = MARK_BASE + index
    if m > MARK_MAX:
        raise ValueError("session mark space exhausted (prototype limit)")
    return m


def block_for_mark(mark: int):
    return mark - MARK_BASE if mark is not None and mark >= MARK_BASE else None


# ---------------------------------------------------------------- per-node copies of the chain
def node_dir():
    d = os.environ.get("NISHAAN_NODE_LEDGERS") or os.path.join(os.path.dirname(os.path.abspath(db.DB_PATH)), "node_ledgers")
    os.makedirs(d, exist_ok=True)
    return d


def _node_names():
    return [n["name"] for n in db.list_nodes()]


def _rconn(name):
    c = sqlite3.connect(os.path.join(node_dir(), f"{name}.db"), timeout=30)
    c.execute("CREATE TABLE IF NOT EXISTS chain (idx INTEGER PRIMARY KEY, block_hash TEXT, block_json TEXT)")
    return c


def _replica(name) -> dict:
    c = _rconn(name)
    rows = c.execute("SELECT idx, block_hash, block_json FROM chain ORDER BY idx").fetchall()
    c.close()
    return {r[0]: (r[1], r[2]) for r in rows}


def _authentic(b: dict, pubs: dict) -> bool:
    """What a node checks before it stores a block: the hash, and >= QUORUM valid node signatures."""
    try:
        if _hash_core(b) != b.get("block_hash"):
            return False
        good = sum(crypto.verify(b["block_hash"].encode(), bytes.fromhex(sg), pubs.get(nm, b""))
                   for nm, sg in b.get("votes", {}).items())
        return good >= QUORUM
    except Exception:
        return False


def sync_node(name):
    """Bring one node's copy up to date. Candidates come from the other nodes' copies first,
    then the main ledger; the node keeps a block only if it checks out itself."""
    pubs = {n["name"]: n["dsa_pub"] for n in db.list_nodes()}
    mine = _replica(name)
    cands = {}
    for other in _node_names():
        if other != name:
            for i, (_, js) in _replica(other).items():
                cands.setdefault(i, []).append(js)
    for r in db.list_blocks(asc=True):
        cands.setdefault(r["idx"], []).append(r["block_json"])
    add = []
    for i in sorted(cands):
        if i in mine:
            continue
        for js in cands[i]:
            b = json.loads(js)
            if b.get("index") == i and _authentic(b, pubs):
                add.append((i, b["block_hash"], js))
                break
    if add:
        c = _rconn(name)
        c.executemany("INSERT OR IGNORE INTO chain VALUES (?,?,?)", add)
        c.commit()
        c.close()
    return len(add)


def sync_all_online():
    for n in db.list_nodes():
        if n["online"]:
            sync_node(n["name"])


def wipe_node_copies():
    d = node_dir()
    for f in os.listdir(d):
        if f.endswith(".db"):
            os.remove(os.path.join(d, f))


def lookup_block(index: int):
    """The record for a ledger index as the NODES hold it (majority of node copies),
    falling back to the main ledger. Returns (block | None, note)."""
    votes = {}
    for name in _node_names():
        r = _replica(name).get(index)
        if r:
            votes.setdefault(r[1], []).append(name)
    main = db.get_block(index)
    if votes:
        js, holders = max(votes.items(), key=lambda kv: len(kv[1]))
        note = ""
        if main is None:
            note = "record is missing from the main ledger but held by " + ", ".join(holders)
        elif main["block_json"] != js:
            note = "main ledger copy differs from the node copies; node copies used"
        return json.loads(js), note
    return (json.loads(main["block_json"]), "not yet held by the nodes") if main else (None, "no such record")


def online_node_names():
    return [n["name"] for n in db.list_nodes() if n["online"]]


# ---------------------------------------------------------------- record an open
def record_open(doc_id, username, officer_id, receipt: dict, officer_sig: bytes, officer_pub: bytes) -> dict:
    with _lock:
        last = db.last_block()
        prev = json.loads(last["block_json"])["block_hash"] if last else GENESIS
        # NB: prev is taken from the stored block_hash of the last block
        block = {
            "index": (last["idx"] + 1) if last else 1,
            "prev_hash": prev,
            "doc_id": doc_id,
            "username": username,
            "officer_id": officer_id,
            "session": receipt["session"],
            "time": receipt["time"],
            "receipt": receipt,
            "receipt_hash": receipt_hash(receipt),
            "officer_sig": officer_sig.hex(),
        }
        bh = _hash_core(block)

        votes, per_node = {}, {}
        for n in db.list_nodes():
            if not n["online"]:
                per_node[n["name"]] = "offline"
                continue
            # each node checks the officer's signature AND the access policy itself before voting
            ok = (block["receipt_hash"] == receipt_hash(receipt)
                  and crypto.verify(block["receipt_hash"].encode(), officer_sig, officer_pub)
                  and policy_check(doc_id, username) is None)
            if not ok:
                per_node[n["name"]] = "rejected"
                continue
            sig = crypto.sign(_node_sk(n), bh.encode())
            votes[n["name"]] = sig.hex()
            per_node[n["name"]] = "signed"

        pubs = {n["name"]: n["dsa_pub"] for n in db.list_nodes()}
        valid = sum(crypto.verify(bh.encode(), bytes.fromhex(s), pubs[name]) for name, s in votes.items())
        block.update(block_hash=bh, votes=votes, valid_votes=valid, quorum=QUORUM,
                     accepted=valid >= QUORUM)
        if block["accepted"]:
            db.save_block(block)
            for name in votes:                      # every approving node stores its own copy
                sync_node(name)
        block["per_node"] = per_node
        return block


# ---------------------------------------------------------------- verification
def verify_chain() -> dict:
    pubs = {n["name"]: n["dsa_pub"] for n in db.list_nodes()}
    users = {u["username"]: u["dsa_pub"] for u in db.list_users()}
    results, prev_stored, all_ok = [], GENESIS, True
    for row in db.list_blocks(asc=True):
        problems = []
        try:
            b = json.loads(row["block_json"])
            if b.get("prev_hash") != prev_stored:
                problems.append("link to previous block is broken")
            if _hash_core(b) != b.get("block_hash"):
                problems.append("contents were changed after sealing (hash mismatch)")
            if receipt_hash(b["receipt"]) != b["receipt_hash"]:
                problems.append("receipt does not match its hash")
            if b["receipt"].get("username") != b["username"] or b["receipt"].get("officer_id") != b["officer_id"]:
                problems.append("officer named in block differs from the signed receipt")
            upub = users.get(b["receipt"].get("username"))
            if not upub or not crypto.verify(b["receipt_hash"].encode(), bytes.fromhex(b["officer_sig"]), upub):
                problems.append("officer signature invalid")
            good = sum(crypto.verify(b["block_hash"].encode(), bytes.fromhex(s), pubs.get(name, b""))
                       for name, s in b.get("votes", {}).items())
            if good < QUORUM:
                problems.append(f"only {good} valid node votes (need {QUORUM})")
            prev_stored = b.get("block_hash")
        except Exception as e:  # malformed JSON etc.
            problems.append(f"block unreadable: {e}")
        results.append({"index": row["idx"], "ok": not problems, "problems": problems, "_json": row["block_json"]})

    # ---- compare the main ledger with every node's own copy
    reps = {name: _replica(name) for name in _node_names()}
    main_idx = {r["index"] for r in results}
    for r in results:
        holders = [n for n in reps if r["index"] in reps[n]]
        agree = [n for n in holders if reps[n][r["index"]][1] == r["_json"]]
        if holders and len(agree) < len(holders):
            r["problems"].append("does not match the copies held by " + ", ".join(n for n in holders if n not in agree))
        elif not holders:
            r["problems"].append("not held by any node (possibly inserted directly into the database)")
        r["ok"] = not r["problems"]
    held = {}
    for n, rows in reps.items():
        for i in rows:
            held.setdefault(i, []).append(n)
    for i in sorted(held):
        if i not in main_idx and len(held[i]) >= QUORUM - 1:
            results.append({"index": i, "ok": False, "deleted": True, "_json": None,
                            "problems": ["deleted from the main ledger; still held by " + ", ".join(held[i])]})
    results.sort(key=lambda r: r["index"])
    for r in results:
        r.pop("_json", None)
        all_ok &= r["ok"]
    top = max(main_idx) if main_idx else 0
    node_view = [{"node": n, "records": len(rows), "up_to_date": all(i in rows for i in main_idx)}
                 for n, rows in reps.items()]
    return {"ok": all_ok, "blocks": results, "checked": len(main_idx), "latest": top, "node_copies": node_view}


# ---------------------------------------------------------------- demo-only tampering
def tamper(index: int, mode: str, new_username: str, new_officer_id: int) -> dict:
    """mode 'edit'   -- quietly rewrite who opened it (as an insider editing the DB would)
       mode 'rehash' -- rewrite it AND recompute the block's hash to try to hide it"""
    row = db.get_block(index)
    if not row:
        return None
    b = json.loads(row["block_json"])
    if mode == "delete":
        db.delete_block(index)
        return b
    b["username"], b["officer_id"] = new_username, new_officer_id
    if mode == "rehash":
        b["block_hash"] = _hash_core(b)
    db.overwrite_block_json(index, json.dumps(b, sort_keys=True))
    return b


def restore_from_nodes() -> int:
    """Rebuild the main ledger from the node copies (majority agreement, each block re-checked)."""
    db.restore_all_blocks()                                   # legacy: the sealed original of each row
    pubs = {n["name"]: n["dsa_pub"] for n in db.list_nodes()}
    reps = [_replica(n) for n in _node_names()]
    fixed = 0
    for i in sorted({i for r in reps for i in r}):
        tally = {}
        for r in reps:
            if i in r:
                tally[r[i][1]] = tally.get(r[i][1], 0) + 1
        js, n = max(tally.items(), key=lambda kv: kv[1])
        if _authentic(json.loads(js), pubs):
            main = db.get_block(i)
            if main is None or main["block_json"] != js:
                db.upsert_block_json(js)
                fixed += 1
    return fixed


def public_block(b: dict) -> dict:
    """Trim the ~3.3 KB signatures down to short fingerprints for display."""
    out = {k: v for k, v in b.items() if k not in ("votes", "officer_sig", "per_node")}
    out["officer_sig_fingerprint"] = crypto.sha3(bytes.fromhex(b["officer_sig"]))[:16]
    out["votes"] = {name: crypto.sha3(bytes.fromhex(s))[:16] for name, s in b.get("votes", {}).items()}
    return out
