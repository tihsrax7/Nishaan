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
     signature, and only then signs block_hash with its own ML-DSA-65 key (a vote).
  4. >= 4 valid votes -> block accepted and appended; else the file stays locked.

verify_chain() re-checks everything from scratch: each hash, each link, each
officer signature, each node vote. tamper() exists only for the demo, to show
that editing any past record is caught.
"""
import json
import time
import threading

from . import crypto, db

N_NODES, QUORUM = 5, 4
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
    if db.count_nodes():
        return
    for i in range(N_NODES):
        pub, sk = crypto.new_sig_keypair()
        db.add_node(f"N{i + 1}", pub, sk, online=(i + 1 != 5))   # demo default: N5 offline -> 4/5


def status():
    return [{"name": n["name"], "online": bool(n["online"]),
             "key_fingerprint": crypto.sha3(n["dsa_pub"])[:16]} for n in db.list_nodes()]


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
            # each node checks the officer's signature itself before voting
            ok = (block["receipt_hash"] == receipt_hash(receipt)
                  and crypto.verify(block["receipt_hash"].encode(), officer_sig, officer_pub))
            if not ok:
                per_node[n["name"]] = "rejected"
                continue
            sig = crypto.sign(n["dsa_sk"], bh.encode())
            votes[n["name"]] = sig.hex()
            per_node[n["name"]] = "signed"

        pubs = {n["name"]: n["dsa_pub"] for n in db.list_nodes()}
        valid = sum(crypto.verify(bh.encode(), bytes.fromhex(s), pubs[name]) for name, s in votes.items())
        block.update(block_hash=bh, votes=votes, valid_votes=valid, quorum=QUORUM,
                     accepted=valid >= QUORUM)
        if block["accepted"]:
            db.save_block(block)
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
        all_ok &= not problems
        results.append({"index": row["idx"], "ok": not problems, "problems": problems})
    return {"ok": all_ok, "blocks": results, "checked": len(results)}


# ---------------------------------------------------------------- demo-only tampering
def tamper(index: int, mode: str, new_username: str, new_officer_id: int) -> dict:
    """mode 'edit'   -- quietly rewrite who opened it (as an insider editing the DB would)
       mode 'rehash' -- rewrite it AND recompute the block's hash to try to hide it"""
    row = db.get_block(index)
    if not row:
        return None
    b = json.loads(row["block_json"])
    b["username"], b["officer_id"] = new_username, new_officer_id
    if mode == "rehash":
        b["block_hash"] = _hash_core(b)
    db.overwrite_block_json(index, json.dumps(b, sort_keys=True))
    return b


def public_block(b: dict) -> dict:
    """Trim the ~3.3 KB signatures down to short fingerprints for display."""
    out = {k: v for k, v in b.items() if k not in ("votes", "officer_sig", "per_node")}
    out["officer_sig_fingerprint"] = crypto.sha3(bytes.fromhex(b["officer_sig"]))[:16]
    out["votes"] = {name: crypto.sha3(bytes.fromhex(s))[:16] for name, s in b.get("votes", {}).items()}
    return out
