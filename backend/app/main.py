"""
OWNER: Person F (wiring) -- everyone's module plugs in here.
NISHAAN v5 API + it also serves the web console itself at http://localhost:8000/

Run (from backend/):
    python3 -m uvicorn app.main:app --port 8000
or from the project root:
    bash start.sh

Endpoints (all JSON unless noted; "auth" = needs Authorization: Bearer <token>):
  GET  /                       the web console (frontend/index.html)
  GET  /health                 liveness + crypto algorithms in use
  POST /login                  {username, password} -> {token, user}
  GET  /me                     auth: who am I
  GET  /users                  auth: roster + public-key fingerprints
  POST /users                  admin: add a person {username, name, password, officer_id?}
  POST /users/{u}/active       admin: {active: true|false} deactivate / reactivate an account
  GET  /nodes                  auth: ledger nodes, online state, key fingerprints
  POST /nodes/toggle           admin: {name, online}
  POST /documents              admin: multipart file + title + classification + recipients (comma list)
                               + expires_hours (0 = no expiry)
  GET  /documents              auth: admin/security see all, officers see only docs shared to them
  POST /documents/{id}/access  admin: {username?, allow} revoke / restore one recipient, or the whole document
  POST /open/{doc_id}          officer (must be a recipient): {password} -> unseal keys, sign -> vote -> unlock
                               -> watermarked file (binary body; metadata in X-Nishaan-Meta header, base64 JSON)
  GET  /ledger                 auth: all accepted blocks (signatures shown as fingerprints)
  GET  /ledger/verify          auth: re-verify every hash, link, officer signature and node vote
  POST /ledger/tamper          admin (demo): {index, mode: edit|rehash, username}
  POST /ledger/restore         admin (demo): undo all tampering
  GET  /ledger/export          admin/security: the full chain + public keys, for offline verification
  POST /trace                  admin/security: multipart doc_id + file (the leaked copy) -> who leaked it;
                               opens a CASE that a second person must confirm (two-person rule)
  GET  /cases                  admin/security: leak cases
  POST /cases/{id}/decision    admin/security (not the person who ran the trace): {approve, note}
  GET  /cases/{id}/report      confirmed cases only: signed PDF evidence report (JSON bundle attached)
  GET  /cases/{id}/bundle      confirmed cases only: signed JSON evidence bundle
  GET  /alerts                 admin/security: insider early-warning alerts + risk ranking
  GET  /audit                  admin/security: audit log, including DENIED attempts
  GET  /audit/verify           admin/security: re-check the audit log's own hash chain
  POST /admin/reset            admin (demo): wipe everything back to a fresh start
"""
import os
import re
import json
import time
import uuid
import base64
import datetime
import shutil

os.environ.setdefault("OPENCV_IO_MAX_IMAGE_PIXELS", str(60_000_000))   # refuse decompression bombs
import numpy as np
import cv2
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse, JSONResponse
from pydantic import BaseModel

from . import crypto, watermark, db, auth, pdf_support, ledger, evidence, alerts

VERSION = "5.1"
MAX_UPLOAD = 30 * 1024 * 1024
MARK_CONFIDENCE_MIN = 0.5
BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.environ.get("NISHAAN_STORE", os.path.join(BACKEND, "store"))
FRONTEND = os.path.join(os.path.dirname(BACKEND), "frontend", "index.html")
CLASSIFICATIONS = ["RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP SECRET"]

app = FastAPI(title="NISHAAN", version=VERSION)
# The console is served by this same server, so browsers need no cross-origin access.
# Only localhost origins are allowed (plus any listed in NISHAAN_ALLOWED_ORIGINS).
ALLOWED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"] + \
    [o.strip() for o in os.environ.get("NISHAAN_ALLOWED_ORIGINS", "").split(",") if o.strip()]
DEMO_MODE = os.environ.get("NISHAAN_DEMO", "1") == "1"      # tamper/restore/reset demo endpoints
MAX_PDF_PAGES = 200
MAX_PIXELS = 60_000_000

app.add_middleware(
    CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Nishaan-Meta", "X-Session", "X-Block-Hash", "X-Votes", "X-Officer",
                    "Content-Disposition"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    resp.headers["Cache-Control"] = "no-store"          # never cache secret documents or API data
    resp.headers["Pragma"] = "no-cache"
    return resp


async def read_upload(file: UploadFile) -> bytes:
    """Read an upload in chunks and stop as soon as it exceeds the limit
    (instead of loading an arbitrarily large body into memory first)."""
    buf = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_UPLOAD:
            raise HTTPException(413, f"file too large (max {MAX_UPLOAD // (1024 * 1024)} MB)")
    if not buf:
        raise HTTPException(400, "the file is empty")
    return bytes(buf)


def decode_image(raw: bytes):
    try:
        img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
    except cv2.error:
        img = None
    if img is not None and img.shape[0] * img.shape[1] > MAX_PIXELS:
        raise HTTPException(413, "image dimensions are too large")
    return img


def safe_pdf_pages(raw: bytes):
    try:
        info = pdf_support.pdf_page_sizes(raw)
    except Exception:
        raise HTTPException(400, "that PDF couldn't be read (damaged or password-protected?)")
    if not info:
        raise HTTPException(400, "that PDF has no pages")
    if len(info) > MAX_PDF_PAGES:
        raise HTTPException(413, f"PDF has too many pages (max {MAX_PDF_PAGES})")
    if any(w * h > MAX_PIXELS for w, h in info):
        raise HTTPException(413, "a PDF page is too large to process")
    return pdf_support.pdf_to_pages(raw)


def all_shares_key(doc_id: str) -> bytes:
    """Forensic key rebuild for tracing (admin/security only): 3 of the 5 stored shares,
    each unsealed with its own node's key file."""
    rows = db.get_shares(doc_id, [n["name"] for n in ledger.status()])
    return crypto.rebuild_key([ledger.open_share(r) for r in rows[:3]])


def bootstrap():
    os.makedirs(STORE, exist_ok=True)
    db.init_db()
    auth.seed_users()
    auth.seal_seed_accounts()
    ledger.seed_nodes()
    ledger.sync_all_online()          # every node keeps (and here catches up) its own copy of the chain
    evidence.authority()


bootstrap()


# ---------------------------------------------------------------- auth helpers
def current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "not logged in")
    claims = auth.verify_token(authorization.split(" ", 1)[1].strip())
    row = db.get_user(claims["username"]) if claims else None
    if not row:
        raise HTTPException(401, "session expired or invalid -- please log in again")
    if not row["active"]:
        raise HTTPException(401, "this account has been deactivated")
    # identity and role come from the database, not from the token's claims
    return {"username": row["username"], "officer_id": row["officer_id"], "name": row["name"],
            "role": row["role"], "exp": claims["exp"]}


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        db.log_event("DENIED", user["username"], None, "tried an admin-only action")
        raise HTTPException(403, "only the Distribution Officer (admin) can do this")
    return user


def staff_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] not in auth.STAFF_ROLES:
        db.log_event("DENIED", user["username"], None, "tried a security-staff action")
        raise HTTPException(403, "only the Distribution Officer or the Security Officer can do this")
    return user


# ---------------------------------------------------------------- basics
@app.get("/", include_in_schema=False)
def console():
    if not os.path.exists(FRONTEND):
        return JSONResponse({"error": "frontend/index.html not found next to backend/"}, 404)
    return FileResponse(FRONTEND, media_type="text/html", headers={"Cache-Control": "no-store"})


@app.get("/health")
def health():
    return {"ok": True, "version": VERSION, "algorithms": {
        "file": "AES-256-GCM", "key_split": "Shamir 3-of-5", "signatures": crypto.SIG_ALG,
        "key_delivery": crypto.KEM_ALG, "hash": "SHA3-256", "passwords": "scrypt",
        "key_storage": "officer keys sealed under their password; node keys + shares sealed under per-node key files"},
        "evidence_authority": evidence.authority_fingerprint(),
        "nodes_online": len(ledger.online_node_names()), "quorum": ledger.QUORUM, "demo_mode": DEMO_MODE}


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginBody):
    token, why = auth.login(body.username, body.password)
    if not token:
        db.log_event("LOGIN_FAILED", body.username.strip().lower()[:40], None, why)
        raise HTTPException(401, why)
    user = auth.verify_token(token)
    db.log_event("LOGIN", user["username"], None, user["role"])
    return {"token": token, "user": user}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return user


@app.get("/users")
def users(user: dict = Depends(current_user)):
    return auth.roster()


class NewUser(BaseModel):
    username: str
    name: str
    password: str
    officer_id: int | None = None


@app.post("/users")
def add_user(body: NewUser, user: dict = Depends(admin_only)):
    row, why = auth.create_user(body.username, body.name, body.password, body.officer_id)
    if not row:
        raise HTTPException(400, why)
    db.log_event("USER_ADDED", user["username"], None, f"{row['name']} ({row['username']}, #{row['officer_id']:02d}) added")
    return next(u for u in auth.roster() if u["username"] == row["username"])


class Activation(BaseModel):
    active: bool


@app.post("/users/{username}/active")
def set_active(username: str, body: Activation, user: dict = Depends(admin_only)):
    row = db.get_user(username.lower())
    if not row:
        raise HTTPException(404, "no such user")
    if row["role"] == "admin":
        raise HTTPException(400, "the Distribution Officer account cannot be deactivated")
    db.set_user_active(row["username"], body.active)
    db.log_event("USER_REACTIVATED" if body.active else "USER_DEACTIVATED", user["username"], None,
                 f"{row['name']} ({row['username']}) {'reactivated' if body.active else 'deactivated'}")
    return next(u for u in auth.roster() if u["username"] == row["username"])


# ---------------------------------------------------------------- nodes
@app.get("/nodes")
def nodes(user: dict = Depends(current_user)):
    return {"nodes": ledger.status(), "quorum": ledger.QUORUM}


class NodeToggle(BaseModel):
    name: str
    online: bool


@app.post("/nodes/toggle")
def toggle_node(body: NodeToggle, user: dict = Depends(admin_only)):
    if body.name not in [n["name"] for n in ledger.status()]:
        raise HTTPException(404, f"no node named {body.name}")
    db.set_node_online(body.name, body.online)
    caught_up = ledger.sync_node(body.name) if body.online else 0     # a node coming back fetches what it missed
    db.log_event("NODE", user["username"], None, f"{body.name} {'online' if body.online else 'offline'}"
                 + (f"; caught up {caught_up} record(s)" if caught_up else ""))
    return {"nodes": ledger.status(), "quorum": ledger.QUORUM}


# ---------------------------------------------------------------- distribute (lock once)
def _doc_status(d):
    if d["revoked"]:
        return "withdrawn"
    if d["expires_at"] and time.time() > d["expires_at"]:
        return "expired"
    return "active"


def _doc_view(d, include_recipients=True):
    out = {"doc_id": d["doc_id"], "title": d["title"], "filename": d["filename"], "doctype": d["doctype"],
           "pages": d["pages"], "classification": d["classification"], "created_by": d["created_by"],
           "created_at": d["created_at"], "opens": db.count_opens(d["doc_id"]),
           "ciphertext_sha3": d["ct_hash"][:16], "expires_at": d["expires_at"], "status": _doc_status(d),
           "visible_mark": bool(d["visible_mark"])}
    if include_recipients:
        out["recipients"] = db.get_recipients(d["doc_id"])
        out["revoked_recipients"] = db.get_revoked_recipients(d["doc_id"])
    return out


@app.post("/documents")
async def share(file: UploadFile = File(...), title: str = Form(""), classification: str = Form("RESTRICTED"),
                recipients: str = Form(""), expires_hours: float = Form(0), visible_mark: bool = Form(False),
                user: dict = Depends(admin_only)):
    raw = await read_upload(file)
    rec = sorted({r.strip().lower() for r in recipients.split(",") if r.strip()}, key=lambda u: (re.sub(r'\d+', '', u), int(re.sub(r'\D', '', u) or 0)))
    officers = {u["username"] for u in auth.roster() if u["role"] == "officer" and u["active"]}
    bad = [r for r in rec if r not in officers]
    if bad:
        raise HTTPException(400, f"unknown or deactivated recipient(s): {', '.join(bad)}")
    if not rec:
        raise HTTPException(400, "pick at least one recipient officer")
    classification = classification.upper() if classification.upper() in CLASSIFICATIONS else "RESTRICTED"
    if not (0 <= expires_hours <= 24 * 365):
        raise HTTPException(400, "the access window must be between 0 (no expiry) and 365 days")
    expires_at = time.time() + expires_hours * 3600 if expires_hours else None

    is_pdf = pdf_support.is_pdf(file.filename or "", raw)
    if is_pdf:
        pages = safe_pdf_pages(raw)
        n_pages, orig_bytes = len(pages), raw
    else:
        img = decode_image(raw)
        if img is None:
            raise HTTPException(400, "upload a PDF or a PNG/JPG image")
        n_pages, orig_bytes = 1, cv2.imencode(".png", img)[1].tobytes()

    doc_id = uuid.uuid4().hex[:12]
    ct, nonce, file_key = crypto.encrypt_file(orig_bytes)
    shares = crypto.split_key(file_key)
    del file_key                                   # server keeps only the 5 shares, never the key

    ct_path = os.path.join(STORE, f"{doc_id}.ct")
    with open(ct_path, "wb") as f:                 # ONLY the ciphertext is stored -- no plaintext copy on disk
        f.write(ct)
    orig_path = ""

    title = (title or os.path.splitext(file.filename or "document")[0]).strip()[:120]
    node_names = [n["name"] for n in ledger.status()]
    db.save_document(doc_id, title, file.filename or "document", "pdf" if is_pdf else "image", n_pages,
                     classification, nonce, ct_path, orig_path, crypto.sha3(ct), user["username"], rec, expires_at,
                     visible_mark)
    # each node's share is sealed under that node's own key file before it is stored
    db.save_shares([(doc_id, node_names[i], shares[i][0], *ledger.seal_share(doc_id, node_names[i], shares[i][1], shares[i][2]))
                    for i in range(len(node_names))])
    del shares
    db.log_event("SHARE", user["username"], doc_id, f"'{title}' [{classification}] -> {', '.join(rec)}"
                 + (f"; access window {expires_hours:g} h" if expires_hours else "")
                 + ("; visible name on copies" if visible_mark else "; copies look identical (invisible mark only)"))
    return {**_doc_view(db.get_document(doc_id)),
            "message": "encrypted with AES-256-GCM; key split 3-of-5 across N1-N5; key itself discarded"}


@app.get("/documents")
def documents(user: dict = Depends(current_user)):
    rows = db.list_documents(None if user["role"] in auth.STAFF_ROLES else user["username"])
    return [_doc_view(d) for d in rows]


class AccessBody(BaseModel):
    allow: bool
    username: str | None = None


@app.post("/documents/{doc_id}/access")
def set_access(doc_id: str, body: AccessBody, user: dict = Depends(admin_only)):
    """Instant revoke: withdraw one officer's access, or the whole document, at once.
    Nodes check this policy before every vote, so a revoked copy can never be opened again."""
    doc = db.get_document(doc_id)
    if doc is None:
        raise HTTPException(404, "no document with that id")
    if body.username:
        u = body.username.strip().lower()
        if not db.was_recipient(doc_id, u):
            raise HTTPException(400, f"{u} was never a recipient of this document")
        db.set_recipient_access(doc_id, u, body.allow)
        db.log_event("ACCESS_RESTORED" if body.allow else "ACCESS_REVOKED", user["username"], doc_id,
                     f"{u} {'may open again' if body.allow else 'can no longer open this document'}")
    else:
        db.set_document_revoked(doc_id, not body.allow)
        db.log_event("ACCESS_RESTORED" if body.allow else "DOC_WITHDRAWN", user["username"], doc_id,
                     "document reinstated" if body.allow else "document withdrawn from every recipient")
    return _doc_view(db.get_document(doc_id))


# ---------------------------------------------------------------- open (sign to open)
def _safe_stem(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(name or "document")[0])[:60] or "document"


class OpenBody(BaseModel):
    password: str = ""


@app.post("/open/{doc_id}")
def open_doc(doc_id: str, body: OpenBody | None = None, user: dict = Depends(current_user)):
    doc = db.get_document(doc_id)
    if doc is None:
        raise HTTPException(404, "no document with that id")
    if user["role"] != "officer":
        raise HTTPException(403, "the Distribution and Security Officers do not open documents; log in as a recipient officer")
    if not db.is_recipient(doc_id, user["username"]):
        why = ("your access to this document was revoked" if db.was_recipient(doc_id, user["username"])
               else "you are not on this document's recipient list")
        db.log_event("DENIED", user["username"], doc_id, why)
        raise HTTPException(403, why + " -- attempt logged")
    status = _doc_status(doc)
    if status != "active":
        why = "the document was withdrawn" if status == "withdrawn" else "the access window for this document has closed"
        db.log_event("DENIED", user["username"], doc_id, why)
        raise HTTPException(410, why + " -- attempt logged")

    # step-up: the officer's private keys are sealed under their password -- unseal them just for this opening
    keys, why = auth.unlock_keys(user["username"], (body.password if body else ""))
    if keys is None:
        db.log_event("DENIED", user["username"], doc_id, "sign-to-open refused: " + why)
        raise HTTPException(429 if "locked" in why else 403, why)
    dsa_sk, kem_sk = keys

    urow = db.get_user(user["username"])
    receipt = {"doc_id": doc_id, "username": user["username"], "officer_id": urow["officer_id"],
               "session": os.urandom(8).hex(), "time": round(time.time(), 3),
               "ciphertext_sha3": doc["ct_hash"], "purpose": "open"}
    rhash = ledger.receipt_hash(receipt)
    officer_sig = crypto.sign(dsa_sk, rhash.encode())                  # "sign to open"
    del dsa_sk

    block = ledger.record_open(doc_id, user["username"], urow["officer_id"], receipt, officer_sig, urow["dsa_pub"])
    votes_view = block["per_node"]
    if not block["accepted"]:
        db.log_event("DENIED", user["username"], doc_id,
                     f"quorum not reached ({block['valid_votes']}/{ledger.N_NODES}, need {ledger.QUORUM})")
        meta = {"votes": votes_view, "valid_votes": block["valid_votes"], "quorum": ledger.QUORUM}
        return JSONResponse(status_code=423, content={
            "detail": f"quorum not reached ({block['valid_votes']}/{ledger.N_NODES} nodes signed, "
                      f"{ledger.QUORUM} needed) -- file stays locked", **meta})

    signed_nodes = [name for name, v in votes_view.items() if v == "signed"][:3]
    rows = db.get_shares(doc_id, signed_nodes)
    file_key = crypto.rebuild_key([ledger.open_share(r) for r in rows])   # each node unseals only its own share

    # key delivery: wrapped under the officer's ML-KEM-768 public key, unwrapped with their (unsealed) secret key
    kem_ct, wnonce, wrapped = crypto.wrap_key_for(urow["kem_pub"], file_key)
    file_key = crypto.unwrap_key(kem_sk, kem_ct, wnonce, wrapped)
    del kem_sk

    with open(doc["ct_path"], "rb") as f:
        ct = f.read()
    if crypto.sha3(ct) != doc["ct_hash"]:
        raise HTTPException(500, "stored ciphertext was modified on disk -- refusing to open")
    raw = crypto.decrypt_file(ct, doc["nonce"], file_key)

    oid = urow["officer_id"]
    # session watermark: the invisible mark carries THIS opening's ledger record number, so a leaked copy
    # points to the exact decryption event (officer, time, session) that is signed on the ledger
    mark_id = ledger.mark_for_block(block["index"])
    visible = bool(doc["visible_mark"])
    # optional visible deterrent (off by default: every copy then looks identical)
    diag = f"{urow['name'].upper()}   #{oid:02d}   NISHAAN COPY"
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    stamp_time = datetime.datetime.fromtimestamp(receipt["time"], ist).strftime("%d %b %Y %H:%M IST").upper()

    def mark(page, n=None, total=None):
        foot = (f"NISHAAN  |  COPY #{oid:02d}  |  {urow['name'].upper()}  |  {doc['classification']}  |  "
                f"{stamp_time}  |  SESSION {receipt['session']}" + (f"  |  PAGE {n}/{total}" if total and total > 1 else ""))
        marked = watermark.embed_pixel(page, mark_id)
        return watermark.visible_stamp(marked, diag, foot) if visible else marked

    if doc["doctype"] == "pdf":
        src = pdf_support.pdf_to_pages(raw)
        pages = [mark(p, i + 1, len(src)) for i, p in enumerate(src)]
        out = pdf_support.pages_to_pdf(pages, mark_id, title=doc["title"])
        media, ext = "application/pdf", "pdf"
    else:
        img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        out = cv2.imencode(".png", mark(img))[1].tobytes()
        media, ext = "image/png", "png"

    fname = f"{_safe_stem(doc['filename'])}__copy-{oid:02d}.{ext}" if visible else f"{_safe_stem(doc['filename'])}.{ext}"
    meta = {"officer_id": oid, "name": urow["name"], "username": user["username"],
            "session": receipt["session"], "block_index": block["index"], "block_hash": block["block_hash"],
            "prev_hash": block["prev_hash"], "receipt_hash": rhash,
            "officer_sig_fingerprint": crypto.sha3(officer_sig)[:16],
            "votes": votes_view, "valid_votes": block["valid_votes"], "quorum": ledger.QUORUM,
            "shares_from": signed_nodes, "kem_ciphertext_bytes": len(kem_ct),
            "kem_ciphertext_fingerprint": crypto.sha3(kem_ct)[:16],
            "title": doc["title"], "classification": doc["classification"], "doctype": doc["doctype"],
            "pages": doc["pages"], "filename": fname, "mark_id": mark_id, "visible_mark": visible}
    db.log_event("OPEN", user["username"], doc_id,
                 f"block #{block['index']}, {block['valid_votes']}/{ledger.N_NODES} votes, session {receipt['session']}, mark {mark_id}")
    return Response(content=out, media_type=media, headers={
        "X-Nishaan-Meta": base64.b64encode(json.dumps(meta).encode()).decode(),
        "X-Session": receipt["session"], "X-Block-Hash": block["block_hash"],
        "X-Votes": f"{block['valid_votes']}/{ledger.N_NODES}", "X-Officer": str(oid),
        "Content-Disposition": f'inline; filename="{fname}"'})


class ProtectEvent(BaseModel):
    doc_id: str
    how: str = ""


@app.post("/events/protect")
def protect_event(body: ProtectEvent, user: dict = Depends(current_user)):
    """The protected viewer reports a blocked screenshot / print attempt; it goes to the audit log + Insider watch."""
    if db.get_document(body.doc_id) is None:
        raise HTTPException(404, "no document with that id")
    how = re.sub(r"[^A-Za-z0-9 +./-]", "", body.how)[:60] or "screenshot"
    db.log_event("SCREENSHOT", user["username"], body.doc_id, f"blocked in the protected viewer ({how})")
    return {"logged": True}


# ---------------------------------------------------------------- ledger
@app.get("/ledger")
def get_ledger(user: dict = Depends(current_user)):
    out = []
    for r in db.list_blocks(asc=False):
        try:
            out.append(ledger.public_block(json.loads(r["block_json"])))
        except Exception:
            out.append({"index": r["idx"], "unreadable": True})
    return out


@app.get("/ledger/verify")
def verify(user: dict = Depends(current_user)):
    return ledger.verify_chain()


@app.get("/ledger/export")
def export_ledger(user: dict = Depends(staff_only)):
    """Everything needed to verify the whole chain OFFLINE (tools/verify_offline.py)."""
    blocks = []
    for r in db.list_blocks(asc=True):
        b = json.loads(r["block_json"])
        b.pop("per_node", None)
        blocks.append(b)
    db.log_event("EXPORT", user["username"], None, f"ledger exported ({len(blocks)} blocks)")
    return {"format": "NISHAAN-ledger/1", "system": {"name": "NISHAAN", "version": VERSION},
            "exported_at": time.time(), "blocks": blocks,
            "public_keys": {"officers": {u["username"]: u["dsa_pub"].hex() for u in db.list_users()},
                            "nodes": {n["name"]: n["dsa_pub"].hex() for n in db.list_nodes()}},
            "quorum": ledger.QUORUM}


class TamperBody(BaseModel):
    index: int
    mode: str = "edit"
    username: str = "bose"


@app.post("/ledger/tamper")
def tamper(body: TamperBody, user: dict = Depends(admin_only)):
    if not DEMO_MODE:
        raise HTTPException(404, "not available outside demo mode")
    mode = body.mode if body.mode in ("edit", "rehash", "delete") else "edit"
    target = db.get_user(body.username.lower())
    if not target and mode != "delete":
        raise HTTPException(400, "unknown officer to frame")
    b = ledger.tamper(body.index, mode, target["username"] if target else "", target["officer_id"] if target else 0)
    if b is None:
        raise HTTPException(404, "no block with that index")
    db.log_event("TAMPER", user["username"], b["doc_id"],
                 f"DEMO: block #{body.index} deleted from the main ledger" if mode == "delete" else
                 f"DEMO: block #{body.index} rewritten to blame {target['username'] if target else '?'} ({mode})")
    return {"tampered": body.index, "verify": ledger.verify_chain()}


@app.post("/ledger/restore")
def restore(user: dict = Depends(admin_only)):
    if not DEMO_MODE:
        raise HTTPException(404, "not available outside demo mode")
    fixed = ledger.restore_from_nodes()
    db.log_event("RESTORE", user["username"], None, f"DEMO: main ledger rebuilt from the node copies ({fixed} record(s) repaired)")
    return ledger.verify_chain()


# ---------------------------------------------------------------- trace a leak
@app.post("/trace")
async def trace(doc_id: str = Form(...), file: UploadFile = File(...), user: dict = Depends(staff_only)):
    doc = db.get_document(doc_id.strip())
    if doc is None:
        raise HTTPException(404, "no document with that id")
    raw = await read_upload(file)
    # rebuild the original in memory from the ciphertext + key shares (never stored in plain form)
    with open(doc["ct_path"], "rb") as f:
        ct = f.read()
    if crypto.sha3(ct) != doc["ct_hash"]:
        raise HTTPException(500, "stored ciphertext was modified on disk")
    ref_raw = crypto.decrypt_file(ct, doc["nonce"], all_shares_key(doc["doc_id"]))

    layers = {"pixel": None, "pixel_confidence": 0.0, "metadata": None, "pages_checked": 0}
    if pdf_support.is_pdf(file.filename or "", raw):
        sus_pages = safe_pdf_pages(raw)
        ref_pages = pdf_support.pdf_to_pages(ref_raw) if doc["doctype"] == "pdf" else \
            [cv2.imdecode(np.frombuffer(ref_raw, np.uint8), cv2.IMREAD_COLOR)]
        results = [watermark.extract_pixel_full(s, r) for s, r in zip(sus_pages, ref_pages)]
        layers["metadata"] = pdf_support.read_pdf_metadata_tag(raw)
    else:
        sus = decode_image(raw)
        if sus is None:
            raise HTTPException(400, "upload the leaked copy as a PDF or PNG/JPG image")
        if doc["doctype"] == "pdf":   # a photo/screenshot of one page: try every page, keep the best
            results = [max((watermark.extract_pixel_full(sus, r) for r in pdf_support.pdf_to_pages(ref_raw)),
                           key=lambda t: t["confidence"])]
        else:
            results = [watermark.extract_pixel_full(sus, cv2.imdecode(np.frombuffer(ref_raw, np.uint8), cv2.IMREAD_COLOR))]

    good = [r for r in results if r["officer_id"] is not None and r["confidence"] >= MARK_CONFIDENCE_MIN]
    layers["pages_checked"] = len(results)
    false_log10, pixel_mark = None, None
    if good:
        vals = [r["officer_id"] for r in good]          # the decoded 16-bit value on each page
        pixel_mark = max(set(vals), key=vals.count)
        mine = [r for r in good if r["officer_id"] == pixel_mark]
        layers["pixel_confidence"] = round(float(np.mean([r["confidence"] for r in mine])), 3)
        layers["pages_agreeing"] = vals.count(pixel_mark)
        # conservative: the strongest single page's bound (pages are not multiplied together)
        false_log10 = round(min(watermark.false_match_log10(r["margins"], r["per_bit"]) for r in mine), 1)
    meta_mark = layers["metadata"]
    layers["pixel_mark"], layers["metadata_mark"] = pixel_mark, meta_mark

    def resolve(mark):
        """mark -> (officer_id, ledger block or None, note). Session marks point to one ledger record."""
        if mark is None:
            return None, None, ""
        idx = ledger.block_for_mark(mark)
        if idx is None:                                   # legacy (v5) copy: the mark is the officer number
            return mark, None, "legacy officer mark"
        blk, note = ledger.lookup_block(idx)
        if blk is None or blk.get("doc_id") != doc_id:
            return None, None, "mark does not match a record of this document"
        return blk["officer_id"], blk, note

    p_off, p_blk, p_note = resolve(pixel_mark)
    m_off, m_blk, _ = resolve(meta_mark)
    layers["pixel"], layers["metadata"] = p_off, m_off   # officer numbers, for display
    traced = p_off if p_off is not None else m_off
    event_blk = p_blk if p_off is not None else m_blk
    urow = db.get_user_by_officer(traced) if traced is not None else None
    if urow is not None and urow["role"] != "officer":    # staff never receive marked copies
        urow = None
    if urow is None:
        db.log_event("TRACE", user["username"], doc_id, "no NISHAAN mark found / unknown officer")
        return {"found": False, "layers": layers,
                "verdict": "No readable NISHAAN mark -- this may not be a copy of this document, "
                           "or it was damaged too heavily."}

    if event_blk is not None:
        blocks = [ledger.public_block(event_blk)]
    else:
        blocks = [ledger.public_block(json.loads(r["block_json"])) for r in db.find_blocks(doc_id, traced)]
    agree = meta_mark is None or pixel_mark is None or meta_mark == pixel_mark
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    if event_blk is not None:
        when_ = datetime.datetime.fromtimestamp(event_blk["time"], ist).strftime("%d %b %Y, %H:%M IST")
        verdict = (f"Leak traced to {urow['name']} (officer #{traced:02d}): the copy comes from ledger record "
                   f"#{event_blk['index']}, opened {when_}, session {event_blk['session']}.")
    else:
        verdict = (f"Leak traced to {urow['name']} (officer #{traced:02d})."
                   + (f" Ledger shows {len(blocks)} signed open(s) of this document by them." if blocks else
                      " WARNING: no signed open by this officer is on the ledger."))
    if not agree:
        verdict += " Note: the two watermark layers disagree -- the file was probably edited."
    if p_note and ("differs" in p_note or "missing" in p_note):
        verdict += f" Note: {p_note}."
    event = ({"block_index": event_blk["index"], "session": event_blk["session"], "time": event_blk["time"],
              "mark_id": pixel_mark if p_blk is not None else meta_mark, "block_hash": event_blk["block_hash"]}
             if event_blk is not None else None)
    result = {"found": True, "officer_id": traced, "name": urow["name"], "username": urow["username"],
              "was_recipient": db.was_recipient(doc_id, urow["username"]), "layers_agree": agree,
              "layers": layers, "ledger_blocks": blocks, "verdict": verdict, "event": event,
              "traced_officer_id": traced, "false_match_log10": false_log10}
    # two-person rule: the finding becomes a CASE that someone else must confirm before it is actionable
    case_id = db.next_case_id()
    db.save_case({"case_id": case_id, "doc_id": doc_id, "officer_id": traced, "username": urow["username"],
                  "leaked_name": (file.filename or "leaked-copy")[:120], "leaked_size": len(raw),
                  "leaked_sha256": crypto.sha256(raw), "leaked_sha3": crypto.sha3(raw),
                  "result": result, "requested_by": user["username"]})
    db.log_event("TRACE", user["username"], doc_id, f"traced to {urow['username']} (#{traced:02d})"
                 + (f", record #{event['block_index']}" if event else "") + f"; case {case_id} awaiting confirmation")
    result.update(case_id=case_id, case_status="PENDING")
    return result


# ---------------------------------------------------------------- leak cases (two-person rule) + evidence
def _case_view(c):
    names = {u["username"]: u["name"] for u in db.list_users()}
    r = json.loads(c["result_json"])
    doc = db.get_document(c["doc_id"])
    return {"case_id": c["case_id"], "doc_id": c["doc_id"], "doc_title": doc["title"] if doc else c["doc_id"],
            "classification": doc["classification"] if doc else "", "officer_id": c["officer_id"],
            "username": c["username"], "name": names.get(c["username"], c["username"]),
            "leaked_name": c["leaked_name"], "leaked_sha256": c["leaked_sha256"], "status": c["status"],
            "requested_by": c["requested_by"], "requested_by_name": names.get(c["requested_by"], c["requested_by"]),
            "requested_at": c["requested_at"], "decided_by": c["decided_by"],
            "decided_by_name": names.get(c["decided_by"], c["decided_by"]) if c["decided_by"] else None,
            "decided_at": c["decided_at"], "note": c["decision_note"], "confidence": r["layers"].get("pixel_confidence"),
            "false_match_log10": r.get("false_match_log10"), "ledger_blocks": len(r.get("ledger_blocks", [])),
            "was_recipient": r.get("was_recipient")}


@app.get("/cases")
def cases(user: dict = Depends(staff_only)):
    return [_case_view(c) for c in db.list_cases()]


class Decision(BaseModel):
    approve: bool
    note: str = ""


@app.post("/cases/{case_id}/decision")
def decide(case_id: str, body: Decision, user: dict = Depends(staff_only)):
    c = db.get_case(case_id)
    if c is None:
        raise HTTPException(404, "no such case")
    if c["status"] != "PENDING":
        raise HTTPException(409, f"this case is already {c['status'].lower()}")
    if c["requested_by"] == user["username"]:
        db.log_event("DENIED", user["username"], c["doc_id"], f"tried to confirm own trace {case_id} (two-person rule)")
        raise HTTPException(403, "two-person rule: the person who ran the trace cannot confirm it -- ask the other officer")
    status = "CONFIRMED" if body.approve else "REJECTED"
    db.decide_case(case_id, status, user["username"], body.note.strip()[:300])
    db.log_event("CASE_" + status, user["username"], c["doc_id"], f"{c['username']} | case {case_id} {status.lower()}")
    return _case_view(db.get_case(case_id))


def _confirmed(case_id):
    c = db.get_case(case_id)
    if c is None:
        raise HTTPException(404, "no such case")
    if c["status"] != "CONFIRMED":
        raise HTTPException(409, "evidence is released only after a second officer confirms the case (two-person rule)")
    return c


@app.get("/cases/{case_id}/report")
def case_report(case_id: str, user: dict = Depends(staff_only)):
    c = _confirmed(case_id)
    pdf = evidence.report_pdf(c, VERSION)
    db.log_event("EVIDENCE", user["username"], c["doc_id"], f"evidence report for case {case_id} exported")
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="NISHAAN_evidence_{case_id}.pdf"'})


@app.get("/cases/{case_id}/bundle")
def case_bundle(case_id: str, user: dict = Depends(staff_only)):
    c = _confirmed(case_id)
    db.log_event("EVIDENCE", user["username"], c["doc_id"], f"evidence bundle for case {case_id} exported")
    return evidence.bundle(c, VERSION)


# ---------------------------------------------------------------- insider early warning
@app.get("/alerts")
def get_alerts(user: dict = Depends(staff_only)):
    return alerts.compute()


# ---------------------------------------------------------------- audit + demo reset
@app.get("/audit")
def audit(user: dict = Depends(staff_only)):
    return [dict(r) for r in db.list_events()]


@app.get("/audit/verify")
def audit_verify(user: dict = Depends(staff_only)):
    ok, n, bad = db.verify_events()
    return {"ok": ok, "checked": n, "first_bad_event": bad}


@app.post("/admin/reset")
def reset(user: dict = Depends(admin_only)):
    if not DEMO_MODE:
        raise HTTPException(404, "not available outside demo mode")
    db.wipe()
    shutil.rmtree(STORE, ignore_errors=True)
    ledger.wipe_node_copies()
    auth.reset_lockouts()
    bootstrap()
    db.log_event("RESET", user["username"], None, "demo reset: all documents, blocks and keys regenerated")
    return {"ok": True}
