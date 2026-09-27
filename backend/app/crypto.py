"""
OWNER: Person A (backend/crypto)
All the real cryptography, via liboqs (post-quantum) + standard libraries:
  - AES-256-GCM            file encryption
  - Shamir 3-of-5          file key split across the 5 ledger nodes
  - ML-DSA-65 (FIPS 204)   signatures: officers sign open-receipts, nodes sign votes
  - ML-KEM-768 (FIPS 203)  the rebuilt file key is delivered to the officer wrapped
                           under that officer's own ML-KEM public key
  - SHA3-256               block hashing / chaining
  - scrypt                 password hashing
Keys are exported/imported as bytes so they persist in SQLite across restarts.
"""
import os
import hashlib
import hmac
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Protocol.SecretSharing import Shamir

SIG_ALG = "ML-DSA-65"
KEM_ALG = "ML-KEM-768"
AAD = b"NISHAAN-v4"


# ---------------------------------------------------------------- file encryption
def encrypt_file(data: bytes):
    """Returns (ciphertext, nonce, file_key)."""
    file_key = os.urandom(32)
    nonce = os.urandom(12)
    return AESGCM(file_key).encrypt(nonce, data, AAD), nonce, file_key


def decrypt_file(ct: bytes, nonce: bytes, file_key: bytes) -> bytes:
    return AESGCM(file_key).decrypt(nonce, ct, AAD)


# ---------------------------------------------------------------- Shamir 3-of-5
def split_key(file_key: bytes, k=3, n=5):
    """32-byte key -> n shares (idx, half1, half2); any k rebuild it.
    (PyCryptodome's Shamir works on 16-byte secrets, so the key is split in two halves.)"""
    a = Shamir.split(k, n, file_key[:16])
    b = Shamir.split(k, n, file_key[16:])
    return [(a[i][0], a[i][1], b[i][1]) for i in range(n)]


def rebuild_key(picked):
    """picked: k or more (idx, half1, half2) tuples."""
    h1 = Shamir.combine([(i, x) for i, x, _ in picked])
    h2 = Shamir.combine([(i, y) for i, _, y in picked])
    return h1 + h2


# ---------------------------------------------------------------- ML-DSA-65 signatures
def new_sig_keypair():
    s = oqs.Signature(SIG_ALG)
    pub = s.generate_keypair()
    return pub, s.export_secret_key()


def sign(secret_key: bytes, msg: bytes) -> bytes:
    return oqs.Signature(SIG_ALG, secret_key=secret_key).sign(msg)


def verify(msg: bytes, signature: bytes, pub: bytes) -> bool:
    try:
        return bool(oqs.Signature(SIG_ALG).verify(msg, signature, pub))
    except Exception:
        return False


# ---------------------------------------------------------------- ML-KEM-768 key delivery
def new_kem_keypair():
    k = oqs.KeyEncapsulation(KEM_ALG)
    pub = k.generate_keypair()
    return pub, k.export_secret_key()


def wrap_key_for(recipient_kem_pub: bytes, file_key: bytes):
    """Sender side: encapsulate to the officer's public key, AES-GCM-wrap the file key
    under the shared secret. Returns (kem_ciphertext, wrap_nonce, wrapped_key)."""
    kem_ct, shared = oqs.KeyEncapsulation(KEM_ALG).encap_secret(recipient_kem_pub)
    nonce = os.urandom(12)
    return kem_ct, nonce, AESGCM(shared).encrypt(nonce, file_key, b"NISHAAN-keywrap")


def unwrap_key(recipient_kem_sk: bytes, kem_ct: bytes, nonce: bytes, wrapped: bytes) -> bytes:
    """Officer side: decapsulate with the officer's secret key and unwrap."""
    shared = oqs.KeyEncapsulation(KEM_ALG, secret_key=recipient_kem_sk).decap_secret(kem_ct)
    return AESGCM(shared).decrypt(nonce, wrapped, b"NISHAAN-keywrap")


# ---------------------------------------------------------------- hashing / passwords
def sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or os.urandom(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def check_password(password: str, salt: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, salt)[1], expected)
