"""
OWNER: Person A (crypto)
Per-node key files. Each ledger node's signing key and its share of every document key
are stored in the database SEALED under that node's own 32-byte key file:

    backend/.node_keys/N1.key ... N5.key      (plus authority.key for evidence signing)

So a copy of the database alone is useless -- rebuilding a document key needs the
database AND at least 3 separate node key files. In a real deployment each file would
live on a different machine / HSM, run by a different command.
Files are created on first start with owner-only permissions and are git-ignored.
"""
import os

KEY_DIR = os.environ.get("NISHAAN_NODE_KEYS",
                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".node_keys"))
_cache: dict[str, bytes] = {}


def key(name: str) -> bytes:
    if name in _cache:
        return _cache[name]
    os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(KEY_DIR, f"{name}.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            k = f.read()
    else:
        k = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
    if len(k) != 32:
        raise RuntimeError(f"node key file {path} is damaged")
    _cache[name] = k
    return k
