"""
OWNER: Person F (wiring) -- everyone's module plugs in here.
NISHAAN v4 API + it also serves the web console itself at http://localhost:8000/

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
  GET  /nodes                  auth: ledger nodes, online state, key fingerprints
  POST /nodes/toggle           admin: {name, online}
  POST /documents              admin: multipart file + title + classification + recipients (comma list)
  GET  /documents              auth: admin sees all, officers see only docs shared to them
  POST /open/{doc_id}          officer (must be a recipient): sign -> vote -> unlock -> watermarked file
                               (binary body; metadata in X-Nishaan-Meta header, base64 JSON)
  GET  /ledger                 auth: all accepted blocks (signatures shown as fingerprints)
  GET  /ledger/verify          auth: re-verify every hash, link, officer signature and node vote
  POST /ledger/tamper          admin (demo): {index, mode: edit|rehash, username}
  POST /ledger/restore         admin (demo): undo all tampering
  POST /trace                  admin: multipart doc_id + file (the leaked copy) -> who leaked it
  GET  /audit                  admin: audit log, including DENIED attempts
  POST /admin/reset            admin (demo): wipe everything back to a fresh start
"""
import os
import re
import json
import time
import uuid
import base64
import shutil

import numpy as np
import cv2
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse, JSONResponse
from pydantic import BaseModel

from . import crypto, watermark, db, auth, pdf_support, ledger

VERSION = "4.0"
MAX_UPLOAD = 30 * 1024 * 1024
MARK_CONFIDENCE_MIN = 0.5
BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.environ.get("NISHAAN_STORE", os.path.join(BACKEND, "store"))
FRONTEND = os.path.join(os.path.dirname(BACKEND), "frontend", "index.html")
CLASSIFICATIONS = ["RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP SECRET"]

app = FastAPI(title="NISHAAN", version=VERSION)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*", "Authorization", "Content-Type"],
    expose_headers=["X-Nishaan-Meta", "X-Session", "X-Block-Hash", "X-Votes", "X-Officer",
                    "Content-Disposition"],
)


def bootstrap():
    os.makedirs(STORE, exist_ok=True)
    db.init_db()
    auth.seed_users()
    ledger.seed_nodes()


bootstrap()


# ---------------------------------------------------------------- auth helpers
def current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "not logged in")
    claims = auth.verify_token(authorization.split(" ", 1)[1].strip())
    if not claims or not db.get_user(claims["username"]):
        raise HTTPException(401, "session expired or invalid -- please log in again")
    return claims


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        db.log_event("DENIED", user["username"], None, "tried an admin-only action")
        raise HTTPException(403, "only the Distribution Officer (admin) can do this")
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
        "key_delivery": crypto.KEM_ALG, "hash": "SHA3-256", "passwords": "scrypt"},
        "nodes_online": len(ledger.online_node_names()), "quorum": ledger.QUORUM}


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
    db.log_event("NODE", user["username"], None, f"{body.name} {'online' if body.online else 'offline'}")
    return {"nodes": ledger.status(), "quorum": ledger.QUORUM}


# ---------------------------------------------------------------- distribute (lock once)
def _doc_view(d, include_recipients=True):
    out = {"doc_id": d["doc_id"], "title": d["title"], "filename": d["filename"], "doctype": d["doctype"],
           "pages": d["pages"], "classification": d["classification"], "created_by": d["created_by"],
           "created_at": d["created_at"], "opens": db.count_opens(d["doc_id"]),
           "ciphertext_sha3": d["ct_hash"][:16]}
    if include_recipients:
        out["recipients"] = db.get_recipients(d["doc_id"])
    return out


@app.post("/documents")
async def share(file: UploadFile = File(...), title: str = Form(""), classification: str = Form("RESTRICTED"),
                recipients: str = Form(""), user: dict = Depends(admin_only)):
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "the file is empty")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, f"file too large (max {MAX_UPLOAD // (1024 * 1024)} MB)")
    rec = sorted({r.strip().lower() for r in recipients.split(",") if r.strip()})
    officers = {u["username"] for u in auth.roster() if u["role"] == "officer"}
    bad = [r for r in rec if r not in officers]
    if bad:
        raise HTTPException(400, f"unknown recipient(s): {', '.join(bad)}")
    if not rec:
        raise HTTPException(400, "pick at least one recipient officer")
    classification = classification.upper() if classification.upper() in CLASSIFICATIONS else "RESTRICTED"

    is_pdf = pdf_support.is_pdf(file.filename or "", raw)
    if is_pdf:
        try:
            pages = pdf_support.pdf_to_pages(raw)
        except Exception:
            raise HTTPException(400, "that PDF couldn't be read (damaged or password-protected?)")
        if not pages:
            raise HTTPException(400, "that PDF has no pages")
        n_pages, orig_bytes = len(pages), raw
    else:
        img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise HTTPException(400, "upload a PDF or a PNG/JPG image")
        n_pages, orig_bytes = 1, cv2.imencode(".png", img)[1].tobytes()

    doc_id = uuid.uuid4().hex[:12]
    ct, nonce, file_key = crypto.encrypt_file(orig_bytes)
    shares = crypto.split_key(file_key)
    del file_key                                   # server keeps only the 5 shares, never the key

    ct_path = os.path.join(STORE, f"{doc_id}.ct")
    orig_path = os.path.join(STORE, f"{doc_id}.ref" + (".pdf" if is_pdf else ".png"))
    with open(ct_path, "wb") as f:
        f.write(ct)
    with open(orig_path, "wb") as f:               # sealed reference copy, used only for tracing
        f.write(orig_bytes)

    title = (title or os.path.splitext(file.filename or "document")[0]).strip()[:120]
    node_names = [n["name"] for n in ledger.status()]
    db.save_document(doc_id, title, file.filename or "document", "pdf" if is_pdf else "image", n_pages,
                     classification, nonce, ct_path, orig_path, crypto.sha3(ct), user["username"], rec)
    db.save_shares([(doc_id, node_names[i], *shares[i]) for i in range(len(node_names))])
    db.log_event("SHARE", user["username"], doc_id, f"'{title}' [{classification}] -> {', '.join(rec)}")
    return {**_doc_view(db.get_document(doc_id)),
            "message": "encrypted with AES-256-GCM; key split 3-of-5 across N1-N5; key itself discarded"}


@app.get("/documents")
def documents(user: dict = Depends(current_user)):
    rows = db.list_documents(None if user["role"] == "admin" else user["username"])
    return [_doc_view(d) for d in rows]


# ---------------------------------------------------------------- open (sign to open)
def _safe_stem(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(name or "document")[0])[:60] or "document"


@app.post("/open/{doc_id}")
def open_doc(doc_id: str, user: dict = Depends(current_user)):
    doc = db.get_document(doc_id)
    if doc is None:
        raise HTTPException(404, "no document with that id")
    if user["role"] == "admin":
        raise HTTPException(403, "the Distribution Officer distributes documents; log in as a recipient officer to open")
    if not db.is_recipient(doc_id, user["username"]):
        db.log_event("DENIED", user["username"], doc_id, "not on the recipient list")
        raise HTTPException(403, "you are not on this document's recipient list -- attempt logged")

    urow = db.get_user(user["username"])
    receipt = {"doc_id": doc_id, "username": user["username"], "officer_id": urow["officer_id"],
               "session": os.urandom(8).hex(), "time": round(time.time(), 3),
               "ciphertext_sha3": doc["ct_hash"], "purpose": "open"}
    rhash = ledger.receipt_hash(receipt)
    officer_sig = crypto.sign(urow["dsa_sk"], rhash.encode())          # "sign to open"

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
    file_key = crypto.rebuild_key([(r["idx"], r["half1"], r["half2"]) for r in rows])

    # key delivery: wrapped under the officer's ML-KEM-768 public key, unwrapped with their secret key
    kem_ct, wnonce, wrapped = crypto.wrap_key_for(urow["kem_pub"], file_key)
    file_key = crypto.unwrap_key(urow["kem_sk"], kem_ct, wnonce, wrapped)

    with open(doc["ct_path"], "rb") as f:
        ct = f.read()
    if crypto.sha3(ct) != doc["ct_hash"]:
        raise HTTPException(500, "stored ciphertext was modified on disk -- refusing to open")
    raw = crypto.decrypt_file(ct, doc["nonce"], file_key)

    oid = urow["officer_id"]
    if doc["doctype"] == "pdf":
        pages = [watermark.embed_pixel(p, oid) for p in pdf_support.pdf_to_pages(raw)]
        out = pdf_support.pages_to_pdf(pages, oid, title=doc["title"])
        media, ext = "application/pdf", "pdf"
    else:
        img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        out = cv2.imencode(".png", watermark.embed_pixel(img, oid))[1].tobytes()
        media, ext = "image/png", "png"

    fname = f"{_safe_stem(doc['filename'])}__copy-{oid:02d}.{ext}"
    meta = {"officer_id": oid, "name": urow["name"], "username": user["username"],
            "session": receipt["session"], "block_index": block["index"], "block_hash": block["block_hash"],
            "prev_hash": block["prev_hash"], "receipt_hash": rhash,
            "officer_sig_fingerprint": crypto.sha3(officer_sig)[:16],
            "votes": votes_view, "valid_votes": block["valid_votes"], "quorum": ledger.QUORUM,
            "shares_from": signed_nodes, "kem_ciphertext_bytes": len(kem_ct),
            "kem_ciphertext_fingerprint": crypto.sha3(kem_ct)[:16],
            "title": doc["title"], "classification": doc["classification"], "doctype": doc["doctype"],
            "pages": doc["pages"], "filename": fname}
    db.log_event("OPEN", user["username"], doc_id,
                 f"block #{block['index']}, {block['valid_votes']}/{ledger.N_NODES} votes, session {receipt['session']}")
    return Response(content=out, media_type=media, headers={
        "X-Nishaan-Meta": base64.b64encode(json.dumps(meta).encode()).decode(),
        "X-Session": receipt["session"], "X-Block-Hash": block["block_hash"],
        "X-Votes": f"{block['valid_votes']}/{ledger.N_NODES}", "X-Officer": str(oid),
        "Content-Disposition": f'inline; filename="{fname}"'})


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


class TamperBody(BaseModel):
    index: int
    mode: str = "edit"
    username: str = "bose"


@app.post("/ledger/tamper")
def tamper(body: TamperBody, user: dict = Depends(admin_only)):
    target = db.get_user(body.username.lower())
    if not target:
        raise HTTPException(400, "unknown officer to frame")
    b = ledger.tamper(body.index, "rehash" if body.mode == "rehash" else "edit", target["username"], target["officer_id"])
    if b is None:
        raise HTTPException(404, "no block with that index")
    db.log_event("TAMPER", user["username"], b["doc_id"],
                 f"DEMO: block #{body.index} rewritten to blame {target['username']} ({body.mode})")
    return {"tampered": body.index, "verify": ledger.verify_chain()}


@app.post("/ledger/restore")
def restore(user: dict = Depends(admin_only)):
    db.restore_all_blocks()
    db.log_event("RESTORE", user["username"], None, "DEMO: all blocks restored to their sealed versions")
    return ledger.verify_chain()


# ---------------------------------------------------------------- trace a leak
@app.post("/trace")
async def trace(doc_id: str = Form(...), file: UploadFile = File(...), user: dict = Depends(admin_only)):
    doc = db.get_document(doc_id.strip())
    if doc is None:
        raise HTTPException(404, "no document with that id")
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "the file is empty")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "file too large")
    with open(doc["orig_path"], "rb") as f:
        ref_raw = f.read()

    layers = {"pixel": None, "pixel_confidence": 0.0, "metadata": None, "pages_checked": 0}
    if pdf_support.is_pdf(file.filename or "", raw):
        try:
            sus_pages = pdf_support.pdf_to_pages(raw)
        except Exception:
            raise HTTPException(400, "that PDF couldn't be read")
        ref_pages = pdf_support.pdf_to_pages(ref_raw) if doc["doctype"] == "pdf" else \
            [cv2.imdecode(np.frombuffer(ref_raw, np.uint8), cv2.IMREAD_COLOR)]
        results = [watermark.extract_pixel_detail(s, r) for s, r in zip(sus_pages, ref_pages)]
        layers["metadata"] = pdf_support.read_pdf_metadata_tag(raw)
    else:
        sus = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if sus is None:
            raise HTTPException(400, "upload the leaked copy as a PDF or PNG/JPG image")
        if doc["doctype"] == "pdf":   # a photo/screenshot of one page: try every page, keep the best
            results = [max((watermark.extract_pixel_detail(sus, r) for r in pdf_support.pdf_to_pages(ref_raw)),
                           key=lambda t: t[1])]
        else:
            results = [watermark.extract_pixel_detail(sus, cv2.imdecode(np.frombuffer(ref_raw, np.uint8), cv2.IMREAD_COLOR))]

    good = [(oid, c) for oid, c, _ in results if oid is not None and c >= MARK_CONFIDENCE_MIN]
    layers["pages_checked"] = len(results)
    if good:
        ids = [oid for oid, _ in good]
        best = max(set(ids), key=ids.count)
        layers["pixel"] = best
        layers["pixel_confidence"] = round(float(np.mean([c for oid, c in good if oid == best])), 3)
        layers["pages_agreeing"] = ids.count(best)

    traced = layers["pixel"] if layers["pixel"] is not None else layers["metadata"]
    urow = db.get_user_by_officer(traced) if traced is not None else None
    if urow is None:
        db.log_event("TRACE", user["username"], doc_id, "no NISHAAN mark found / unknown officer")
        return {"found": False, "layers": layers,
                "verdict": "No readable NISHAAN mark -- this may not be a copy of this document, "
                           "or it was damaged too heavily."}

    blocks = [ledger.public_block(json.loads(r["block_json"])) for r in db.find_blocks(doc_id, traced)]
    agree = layers["metadata"] is None or layers["pixel"] is None or layers["metadata"] == layers["pixel"]
    verdict = (f"Leak traced to {urow['name']} (officer #{traced:02d})."
               + (f" Ledger shows {len(blocks)} signed open(s) of this document by them." if blocks else
                  " WARNING: no signed open by this officer is on the ledger."))
    if not agree:
        verdict += " Note: the two watermark layers disagree -- the file was probably edited."
    db.log_event("TRACE", user["username"], doc_id, f"traced to {urow['username']} (#{traced:02d})")
    return {"found": True, "officer_id": traced, "name": urow["name"], "username": urow["username"],
            "was_recipient": db.is_recipient(doc_id, urow["username"]), "layers_agree": agree,
            "layers": layers, "ledger_blocks": blocks, "verdict": verdict,
            "traced_officer_id": traced}


# ---------------------------------------------------------------- audit + demo reset
@app.get("/audit")
def audit(user: dict = Depends(admin_only)):
    return [dict(r) for r in db.list_events()]


@app.post("/admin/reset")
def reset(user: dict = Depends(admin_only)):
    db.wipe()
    shutil.rmtree(STORE, ignore_errors=True)
    auth.reset_lockouts()
    bootstrap()
    db.log_event("RESET", user["username"], None, "demo reset: all documents, blocks and keys regenerated")
    return {"ok": True}
