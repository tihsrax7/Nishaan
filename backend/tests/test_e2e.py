"""
NISHAAN v5 end-to-end check. Plain script (not pytest): prints PASS/FAIL per check.
Run from backend/ with the server ALREADY running on a FRESH database:

    python3 -m uvicorn app.main:app --port 8000 &
    python3 tests/test_e2e.py

(tests/run_10x.py does the fresh start for you, 10 times in a row.)
"""
import os
import sys
import json
import time
import base64
import tempfile
import subprocess

import requests
import pymupdf
import numpy as np
import cv2

API = os.environ.get("NISHAAN_API", "http://localhost:8000")
VERIFIER = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools", "verify_offline.py")
TMP = tempfile.mkdtemp(prefix="nishaan_test_")
FAILS = []


def check(name, cond, detail=""):
    ok = bool(cond)
    print(("PASS" if ok else "FAIL") + f" - {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)
    return ok


def T(name):
    return os.path.join(TMP, name)


# ---------------------------------------------------------------- sample files
def make_sample_pdf(path, pages=2):
    doc = pymupdf.open()
    for i in range(pages):
        page = doc.new_page(width=620, height=800)
        page.draw_rect(pymupdf.Rect(0, 700, 620, 800), color=(0.8, 0.1, 0.1), fill=(0.8, 0.1, 0.1))
        page.insert_textbox((50, 50, 570, 680),
                            f"RESTRICTED\nSample order, page {i + 1}.\nNot a real document.\n" * 8, fontsize=14)
    doc.save(path)
    doc.close()


def make_sample_colour_image(path, w=2400, h=1800):
    img = np.zeros((h, w, 3), np.uint8)
    img[:] = (60, 140, 210)
    img[h // 2:, :] = (170, 90, 40)
    for y in range(120, h // 2 - 40, 70):
        cv2.putText(img, "RESTRICTED - sample page, not a real document", (80, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 1.4, (20, 20, 20), 3)
    cv2.imwrite(path, img)


def login(u, p=None):
    return requests.post(f"{API}/login", json={"username": u, "password": p or f"{u}123"})


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def meta_of(r):
    return json.loads(base64.b64decode(r.headers["X-Nishaan-Meta"]))


def share(tok, path, recipients, title="Test doc", cls="SECRET", mime=None, expires=None, visible=False):
    name = os.path.basename(path)
    data = {"title": title, "classification": cls, "recipients": ",".join(recipients),
            "visible_mark": "true" if visible else "false"}
    if expires is not None:
        data["expires_hours"] = str(expires)
    return requests.post(f"{API}/documents", headers=H(tok), data=data,
                         files={"file": (name, open(path, "rb"), mime or "application/octet-stream")})


def opn(tok, doc_id, password):
    """Sign to open: the officer re-enters their password to unseal their signing key."""
    return requests.post(f"{API}/open/{doc_id}", headers=H(tok), json={"password": password})


def verifier(*args):
    return subprocess.run([sys.executable, VERIFIER, *args], capture_output=True, text=True)


def trace(tok, doc_id, path, mime="application/octet-stream"):
    return requests.post(f"{API}/trace", headers=H(tok), data={"doc_id": doc_id},
                         files={"file": (os.path.basename(path), open(path, "rb"), mime)})


def set_nodes(tok, offline):
    for n in ["N1", "N2", "N3", "N4", "N5"]:
        requests.post(f"{API}/nodes/toggle", headers=H(tok), json={"name": n, "online": n not in offline})


def main():
    make_sample_pdf(T("sample.pdf"))
    make_sample_colour_image(T("colour.png"))

    # ---------------------------------------------------------------- basics
    r = requests.get(f"{API}/health")
    check("health endpoint answers", r.status_code == 200 and r.json()["algorithms"]["signatures"] == "ML-DSA-65")
    r = requests.get(f"{API}/")
    check("web console is served at /", r.status_code == 200 and "NISHAAN" in r.text)

    # ---------------------------------------------------------------- login
    r = login("admin")
    check("admin login works", r.status_code == 200 and r.json()["user"]["role"] == "admin")
    adm = r.json()["token"]
    r = login("officer1")
    check("officer login works", r.status_code == 200 and r.json()["user"]["officer_id"] == 1)
    rao = r.json()["token"]
    iyer = login("officer2").json()["token"]
    bose = login("officer3").json()["token"]
    check("wrong password rejected", login("officer1", "nope").status_code == 401)
    check("unknown user rejected", login("ghost", "x").status_code == 401)
    for _ in range(5):
        login("officer4", "wrong")
    r = login("officer4")
    check("account locks after 5 wrong passwords", r.status_code == 401 and "locked" in r.text, r.text)
    check("no token -> 401", requests.get(f"{API}/documents").status_code == 401)
    check("garbage token -> 401", requests.get(f"{API}/documents", headers=H("garbage")).status_code == 401)
    r = requests.get(f"{API}/users", headers=H(rao))
    check("roster lists 12 users (admin + security + officer1-10) with key fingerprints",
          r.status_code == 200 and len(r.json()) == 12 and all(u["dsa_pub_fingerprint"] for u in r.json()))

    # ---------------------------------------------------------------- roles
    r = share(rao, T("colour.png"), ["officer1"])
    check("officer can NOT share documents (admin only)", r.status_code == 403)
    check("officer can NOT toggle nodes", requests.post(f"{API}/nodes/toggle", headers=H(rao),
                                                         json={"name": "N1", "online": False}).status_code == 403)
    check("officer can NOT read the audit log", requests.get(f"{API}/audit", headers=H(rao)).status_code == 403)

    set_nodes(adm, ["N5"])
    r = requests.get(f"{API}/nodes", headers=H(rao))
    check("nodes: 4 online, quorum 4", sum(n["online"] for n in r.json()["nodes"]) == 4 and r.json()["quorum"] == 4)

    # ---------------------------------------------------------------- share validation
    check("share with no recipients rejected", share(adm, T("colour.png"), []).status_code == 400)
    check("share with unknown recipient rejected", share(adm, T("colour.png"), ["nobody"]).status_code == 400)
    open(T("junk.bin"), "wb").write(b"not a real file" * 10)
    check("share of a non-image/non-PDF rejected", share(adm, T("junk.bin"), ["officer1"]).status_code == 400)

    # ---------------------------------------------------------------- image: share -> open -> trace
    r = share(adm, T("colour.png"), ["officer1", "officer2"], title="Harbour photo", cls="SECRET", mime="image/png")
    check("admin shares an image to rao + iyer", r.status_code == 200, r.text)
    img_id = r.json()["doc_id"]
    check("share stores recipients + classification",
          r.json()["recipients"] == ["officer1", "officer2"] and r.json()["classification"] == "SECRET")

    docs_rao = requests.get(f"{API}/documents", headers=H(rao)).json()
    docs_bose = requests.get(f"{API}/documents", headers=H(bose)).json()
    check("rao's inbox shows the doc", any(d["doc_id"] == img_id for d in docs_rao))
    check("bose's inbox does NOT show it", not any(d["doc_id"] == img_id for d in docs_bose))

    r = requests.post(f"{API}/open/{img_id}", headers=H(bose))
    check("non-recipient (bose) is refused with 403", r.status_code == 403)
    r = requests.post(f"{API}/open/{img_id}", headers=H(adm))
    check("admin cannot open (distributes only)", r.status_code == 403)
    check("unknown doc id -> 404", requests.post(f"{API}/open/ffffffffffff", headers=H(rao)).status_code == 404)

    t0 = time.time()
    r = opn(rao, img_id, "officer1123")
    t_open = time.time() - t0
    check("rao opens the image (4/5 quorum)", r.status_code == 200, r.text[:200])
    check("open is fast (< 3 s)", t_open < 3, f"{t_open:.1f}s")
    m = meta_of(r)
    check("meta: officer 1, 4 valid votes, N5 offline",
          m["officer_id"] == 1 and m["valid_votes"] == 4 and m["votes"]["N5"] == "offline", m)
    check("meta: key was delivered via ML-KEM-768 (1088-byte ciphertext)", m["kem_ciphertext_bytes"] == 1088)
    check("meta: copy's file name does not reveal the reader", "__copy-" not in m["filename"] and not m["visible_mark"], m["filename"])
    check("meta: session mark = 1024 + this opening's ledger record", m["mark_id"] == 1024 + m["block_index"], m)
    m_first = m
    open(T("rao.png"), "wb").write(r.content)

    opened = cv2.imread(T("rao.png"), cv2.IMREAD_COLOR)
    orig = cv2.imread(T("colour.png"), cv2.IMREAD_COLOR)
    check("opened image keeps its colour", opened is not None and
          np.abs(opened[:, :, 0].astype(int) - opened[:, :, 2].astype(int)).mean() > 20)
    body = slice(0, int(opened.shape[0] * 0.9))
    check("opened image still looks like the original (body changed only slightly)",
          np.abs(opened[body].astype(int) - orig[body].astype(int)).mean() < 8)
    foot = opened[-8:, :].astype(int).mean()
    check("default copy has NO visible band: it looks like the original", np.abs(opened[-8:].astype(int) - orig[-8:].astype(int)).mean() < 8, foot)

    r = trace(adm, img_id, T("rao.png"))
    j = r.json()
    check("trace names rao (#01)", r.status_code == 200 and j["found"] and j["officer_id"] == 1, j)
    check("trace has high confidence", j["layers"]["pixel_confidence"] > 0.8, j["layers"])
    check("trace links to rao's ledger block", len(j["ledger_blocks"]) == 1 and j["was_recipient"])

    small = cv2.resize(opened, (opened.shape[1] // 2, opened.shape[0] // 2))
    cv2.imwrite(T("leak_small.jpg"), small, [cv2.IMWRITE_JPEG_QUALITY, 75])
    j = trace(adm, img_id, T("leak_small.jpg")).json()
    check("trace survives shrink-to-half + JPEG-75", j.get("officer_id") == 1, j)

    r = opn(iyer, img_id, "officer2123")
    open(T("iyer.png"), "wb").write(r.content)
    j = trace(adm, img_id, T("iyer.png")).json()
    check("iyer's copy traces to iyer (#02), not rao", j.get("officer_id") == 2, j)

    j = trace(adm, img_id, T("colour.png")).json()
    check("the unmarked original is NOT blamed on anyone", j["found"] is False, j)
    check("officer can NOT run a trace", trace(rao, img_id, T("rao.png")).status_code == 403)

    # ---------------------------------------------------------------- PDF
    r = share(adm, T("sample.pdf"), ["officer1"], title="Movement order", cls="TOP SECRET", mime="application/pdf")
    check("admin shares a 2-page PDF", r.status_code == 200 and r.json()["pages"] == 2, r.text)
    pdf_id = r.json()["doc_id"]
    r = opn(rao, pdf_id, "officer1123")
    check("rao opens the PDF", r.status_code == 200 and r.headers["content-type"] == "application/pdf")
    open(T("rao.pdf"), "wb").write(r.content)
    pd = pymupdf.open(T("rao.pdf"))
    check("opened PDF has 2 pages + our title", len(pd) == 2 and pd.metadata["title"] == "Movement order")
    px = pd[0].get_pixmap(clip=pymupdf.Rect(10, 720, 60, 780)).pixel(10, 10)
    check("opened PDF keeps colour (red band still red)", px[0] > 150 and px[1] < 100 and px[2] < 100, px)
    fp = pd[0].get_pixmap(clip=pymupdf.Rect(0, 796, 620, 800)).pixel(300, 1)
    check("default PDF copy has NO dark visible footer band", sum(fp) > 200, fp)
    pd.close()
    j = trace(adm, pdf_id, T("rao.pdf"), "application/pdf").json()
    check("PDF trace: both layers name rao", j.get("officer_id") == 1 and j["layers"]["metadata"] == 1
          and j["layers"]["pixel"] == 1 and j["layers_agree"], j)

    # a single page screenshotted and saved as a JPEG
    pg = pymupdf.open(T("rao.pdf"))[1].get_pixmap(dpi=150)
    rgb = np.frombuffer(pg.samples, np.uint8).reshape(pg.height, pg.width, pg.n)[:, :, :3]
    cv2.imwrite(T("page2.jpg"), cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, 85])
    j = trace(adm, pdf_id, T("page2.jpg")).json()
    check("PDF trace from a single-page JPEG screenshot", j.get("officer_id") == 1, j)

    # metadata stripped -> pixel layer still works
    pd = pymupdf.open(T("rao.pdf"))
    pd.set_metadata({})
    pd.save(T("stripped.pdf"))
    pd.close()
    j = trace(adm, pdf_id, T("stripped.pdf"), "application/pdf").json()
    check("PDF trace survives stripped metadata (pixel layer)",
          j.get("officer_id") == 1 and j["layers"]["metadata"] is None, j)

    make_sample_pdf(T("big.pdf"), 30)
    big_id = share(adm, T("big.pdf"), ["officer1"], mime="application/pdf").json()["doc_id"]
    t0 = time.time()
    r = opn(rao, big_id, "officer1123")
    t_big = time.time() - t0
    check("30-page PDF opens in < 10 s", r.status_code == 200 and t_big < 10, f"{t_big:.1f}s")
    check("30-page PDF output < 15 MB", len(r.content) < 15_000_000, f"{len(r.content) // 1_000_000} MB")

    # ---------------------------------------------------------------- quorum
    set_nodes(adm, ["N4", "N5"])
    r = opn(rao, img_id, "officer1123")
    check("with only 3 nodes online the file stays LOCKED (423)", r.status_code == 423, r.text)
    check("locked reply explains the vote", r.json().get("valid_votes") == 3)
    set_nodes(adm, [])
    r = opn(rao, img_id, "officer1123")
    check("with all 5 nodes online: 5/5 votes", r.status_code == 200 and meta_of(r)["valid_votes"] == 5)
    set_nodes(adm, ["N5"])

    # ---------------------------------------------------------------- ledger + verification + tamper
    blocks = requests.get(f"{API}/ledger", headers=H(rao)).json()
    check("ledger has one block per successful open (5)", len(blocks) == 5, len(blocks))
    check("ledger shows fingerprints, not raw 3.3 KB signatures",
          all(len(v) == 16 for b in blocks for v in b["votes"].values()) and all("officer_sig" not in b for b in blocks))
    idx = sorted(b["index"] for b in blocks)
    check("block indexes are 1..5 in order", idx == [1, 2, 3, 4, 5], idx)
    v = requests.get(f"{API}/ledger/verify", headers=H(rao)).json()
    check("fresh chain verifies clean", v["ok"] and v["checked"] == 5, v)

    r = requests.post(f"{API}/ledger/tamper", headers=H(rao), json={"index": 2})
    check("officer can NOT tamper", r.status_code == 403)
    r = requests.post(f"{API}/ledger/tamper", headers=H(adm), json={"index": 2, "mode": "edit", "username": "officer3"})
    v = r.json()["verify"]
    bad = [b["index"] for b in v["blocks"] if not b["ok"]]
    check("editing block #2 is detected at block #2", not v["ok"] and bad == [2], v)
    requests.post(f"{API}/ledger/restore", headers=H(adm))
    r = requests.post(f"{API}/ledger/tamper", headers=H(adm), json={"index": 2, "mode": "rehash", "username": "officer3"})
    v = r.json()["verify"]
    bad = [b["index"] for b in v["blocks"] if not b["ok"]]
    check("edit + recomputed hash is STILL caught (votes + next link break)", not v["ok"] and 2 in bad and 3 in bad, v)
    v = requests.post(f"{API}/ledger/restore", headers=H(adm)).json()
    check("restore makes the chain verify clean again", v["ok"], v)

    # ---------------------------------------------------------------- v5.1: node copies catch a deleted record
    nc = v.get("node_copies", [])
    check("every node keeps its own copy of the ledger", len(nc) == 5 and all(n["up_to_date"] for n in nc), nc)
    r = requests.post(f"{API}/ledger/tamper", headers=H(adm), json={"index": 5, "mode": "delete"})
    v = r.json()["verify"]
    dele = [b for b in v["blocks"] if b.get("deleted")]
    check("deleting the newest record is caught by the node copies",
          not v["ok"] and len(dele) == 1 and dele[0]["index"] == 5 and "still held by" in dele[0]["problems"][0], v)
    v = requests.post(f"{API}/ledger/restore", headers=H(adm)).json()
    check("restore rebuilds the deleted record from the node copies", v["ok"] and v["checked"] == 5, v)
    nodes = requests.get(f"{API}/nodes", headers=H(adm)).json()["nodes"]
    check("node status shows each node's own record count", all(n.get("records_held") == 5 for n in nodes), nodes)

    # ---------------------------------------------------------------- v5.1: identical copies, one mark per opening
    a_ = cv2.imread(T("rao.png")).astype(float)
    b_ = cv2.imread(T("iyer.png")).astype(float)
    mse = ((a_ - b_) ** 2).mean()
    psnr = 10 * np.log10(255 ** 2 / mse) if mse else 99
    check("two officers' copies look identical (PSNR > 36 dB) yet trace apart", psnr > 36, f"{psnr:.1f} dB")
    r2 = opn(rao, img_id, "officer1123")
    m2 = meta_of(r2)
    open(T("rao2.png"), "wb").write(r2.content)
    j = trace(adm, img_id, T("rao2.png")).json()
    ev = j.get("event") or {}
    check("a second copy of the same officer traces to its OWN opening (record + session)",
          j.get("officer_id") == 1 and ev.get("block_index") == m2["block_index"] and ev.get("session") == m2["session"], ev)
    j1 = trace(adm, img_id, T("rao.png")).json()
    check("the first copy still traces to the first opening", (j1.get("event") or {}).get("block_index") == m_first["block_index"]
          != m2["block_index"], j1.get("event"))
    vr = share(adm, T("colour.png"), ["officer1"], title="Deterrent copy", visible=True)
    check("sender can switch on the visible name (deterrent)", vr.status_code == 200 and vr.json().get("visible_mark") is True, vr.text[:200])
    vid = vr.json()["doc_id"]
    rv = opn(rao, vid, "officer1123")
    mv = meta_of(rv)
    open(T("vis.png"), "wb").write(rv.content)
    ov = cv2.imread(T("vis.png"))
    check("deterrent copy carries a VISIBLE footer band and a named file",
          ov[-8:].astype(int).mean() < 70 and mv["filename"].endswith("__copy-01.png") and mv["visible_mark"], mv["filename"])
    check("deterrent copy still traces to its exact opening",
          (trace(adm, vid, T("vis.png")).json().get("event") or {}).get("block_index") == mv["block_index"])

    # ---------------------------------------------------------------- people management
    r = requests.post(f"{API}/users", headers=H(rao), json={"username": "nair", "name": "Lt. Priya Nair", "password": "nair123"})
    check("officer can NOT add people", r.status_code == 403)
    r = requests.post(f"{API}/users", headers=H(adm), json={"username": "nair", "name": "Lt. Priya Nair", "password": "nair123"})
    check("admin adds a new officer", r.status_code == 200 and r.json()["officer_id"] == 11 and r.json()["active"], r.text)
    check("new officer is issued their own keys", len(r.json().get("dsa_pub_fingerprint", "")) == 16)
    r = requests.post(f"{API}/users", headers=H(adm), json={"username": "nair", "name": "Someone", "password": "xxxxxx"})
    check("duplicate username rejected", r.status_code == 400)
    r = requests.post(f"{API}/users", headers=H(adm), json={"username": "Bad Name!", "name": "X Y", "password": "xxxxxx"})
    check("invalid username rejected", r.status_code == 400)
    r = requests.post(f"{API}/users", headers=H(adm), json={"username": "shortpw", "name": "X Y", "password": "123"})
    check("too-short password rejected", r.status_code == 400)
    r = login("nair")
    check("new officer can sign in", r.status_code == 200 and r.json()["user"]["name"] == "Lt. Priya Nair")
    nair = r.json()["token"]
    nid = share(adm, T("colour.png"), ["nair"], title="For Nair", mime="image/png").json()["doc_id"]
    r = opn(nair, nid, "nair123")
    check("new officer opens a document shared with them", r.status_code == 200 and meta_of(r)["name"] == "Lt. Priya Nair")
    open(T("nair.png"), "wb").write(r.content)
    j = trace(adm, nid, T("nair.png")).json()
    check("new officer's copy traces back to them (#11)", j.get("officer_id") == 11 and j.get("username") == "nair", j)
    r = requests.post(f"{API}/users/nair/active", headers=H(adm), json={"active": False})
    check("admin deactivates the officer", r.status_code == 200 and r.json()["active"] is False)
    check("deactivated officer can no longer sign in", login("nair").status_code == 401)
    check("deactivated officer's existing session is cut off", requests.get(f"{API}/documents", headers=H(nair)).status_code == 401)
    check("deactivated officer can't be a recipient", share(adm, T("colour.png"), ["nair"]).status_code == 400)
    check("admin account can't be deactivated", requests.post(f"{API}/users/admin/active", headers=H(adm), json={"active": False}).status_code == 400)
    v = requests.get(f"{API}/ledger/verify", headers=H(adm)).json()
    check("ledger still verifies after deactivation (history kept)", v["ok"], v)
    requests.post(f"{API}/users/nair/active", headers=H(adm), json={"active": True})
    check("reactivated officer can sign in again", login("nair").status_code == 200)

    # ---------------------------------------------------------------- v5: sealed keys + sign-to-open
    r = requests.post(f"{API}/open/{img_id}", headers=H(rao))
    check("opening WITHOUT the officer's password is refused (keys stay sealed)", r.status_code == 403, r.status_code)
    r = opn(rao, img_id, "not-my-password")
    check("opening with a WRONG password is refused", r.status_code == 403, r.status_code)
    roster = requests.get(f"{API}/users", headers=H(adm)).json()
    check("every account's private keys are sealed", all(u["keys_sealed"] for u in roster), roster)
    check("health reports sealed key storage", "sealed" in requests.get(f"{API}/health").json()["algorithms"]["key_storage"])

    # ---------------------------------------------------------------- v5: access window + instant revoke
    r = share(adm, T("colour.png"), ["officer1"], title="Short window", mime="image/png", expires=0.001)
    sid = r.json()["doc_id"]
    check("share with an access window records the expiry", r.status_code == 200 and r.json()["expires_at"], r.text)
    check("officer opens inside the access window", opn(rao, sid, "officer1123").status_code == 200)
    time.sleep(4)
    r = opn(rao, sid, "officer1123")
    check("after the window closes the document stays locked (410)", r.status_code == 410, r.status_code)
    check("the document now shows as expired", next(d for d in requests.get(f"{API}/documents", headers=H(adm)).json()
                                                   if d["doc_id"] == sid)["status"] == "expired")
    check("a bad access window is rejected", share(adm, T("colour.png"), ["officer1"], expires=-5).status_code == 400)

    wid = share(adm, T("colour.png"), ["officer1", "officer2"], title="Revocable", mime="image/png").json()["doc_id"]
    r = requests.post(f"{API}/documents/{wid}/access", headers=H(rao), json={"username": "officer2", "allow": False})
    check("an officer can NOT revoke access", r.status_code == 403)
    r = requests.post(f"{API}/documents/{wid}/access", headers=H(adm), json={"username": "officer2", "allow": False})
    check("admin revokes officer2's access instantly", r.status_code == 200 and r.json()["revoked_recipients"] == ["officer2"], r.text)
    r = opn(iyer, wid, "officer2123")
    check("revoked officer can't open it, even with the right password", r.status_code == 403 and "revoked" in r.text, r.text)
    check("revoked document disappears from that officer's list",
          all(d["doc_id"] != wid for d in requests.get(f"{API}/documents", headers=H(iyer)).json()))
    check("other recipients are unaffected", opn(rao, wid, "officer1123").status_code == 200)
    requests.post(f"{API}/documents/{wid}/access", headers=H(adm), json={"username": "officer2", "allow": True})
    check("restored officer can open again", opn(iyer, wid, "officer2123").status_code == 200)
    r = requests.post(f"{API}/documents/{wid}/access", headers=H(adm), json={"allow": False})
    check("admin withdraws the whole document", r.status_code == 200 and r.json()["status"] == "withdrawn")
    check("withdrawn document can't be opened by anyone (410)", opn(rao, wid, "officer1123").status_code == 410)
    requests.post(f"{API}/documents/{wid}/access", headers=H(adm), json={"allow": True})
    check("reinstated document opens again", opn(rao, wid, "officer1123").status_code == 200)

    # ---------------------------------------------------------------- v5: two-person rule + evidence
    r = login("security")
    check("Security Officer can sign in", r.status_code == 200 and r.json()["user"]["role"] == "security")
    sec = r.json()["token"]
    check("Security Officer can NOT share documents", share(sec, T("colour.png"), ["officer1"]).status_code == 403)
    check("Security Officer can NOT open documents", opn(sec, img_id, "security123").status_code == 403)
    check("officers can NOT see leak cases", requests.get(f"{API}/cases", headers=H(rao)).status_code == 403)
    check("officers can NOT see insider alerts", requests.get(f"{API}/alerts", headers=H(rao)).status_code == 403)

    j = trace(adm, img_id, T("rao.png")).json()
    case = j.get("case_id")
    check("a trace opens a case that is PENDING until a second person confirms", case and j["case_status"] == "PENDING", j)
    check("trace reports the chance of a wrong match (< 1 in a trillion)", (j.get("false_match_log10") or 0) <= -12, j.get("false_match_log10"))
    check("evidence is NOT released before confirmation",
          requests.get(f"{API}/cases/{case}/report", headers=H(adm)).status_code == 409)
    r = requests.post(f"{API}/cases/{case}/decision", headers=H(adm), json={"approve": True})
    check("two-person rule: the person who ran the trace can NOT confirm it", r.status_code == 403, r.text)
    r = requests.post(f"{API}/cases/{case}/decision", headers=H(rao), json={"approve": True})
    check("an officer can NOT confirm a case", r.status_code == 403)
    r = requests.post(f"{API}/cases/{case}/decision", headers=H(sec), json={"approve": True, "note": "Matches ledger block"})
    check("Security Officer confirms the case", r.status_code == 200 and r.json()["status"] == "CONFIRMED"
          and r.json()["decided_by"] == "security", r.text)
    check("a decided case can't be decided again",
          requests.post(f"{API}/cases/{case}/decision", headers=H(sec), json={"approve": False}).status_code == 409)
    r = requests.get(f"{API}/cases/{case}/report", headers=H(adm))
    check("confirmed case gives a PDF evidence report", r.status_code == 200 and r.content[:4] == b"%PDF")
    open(T("evidence.pdf"), "wb").write(r.content)
    ep = pymupdf.open(T("evidence.pdf"))
    txt = "".join(p.get_text() for p in ep)
    check("report names the officer, the hashes and the Section 63 data",
          "Officer 1" in txt and "SHA-256" in txt and "section 63" in txt.lower() and "nishaan-evidence.json" in ep.embfile_names())
    ep.close()
    v = verifier(T("evidence.pdf"), T("rao.png"))
    check("OFFLINE verifier accepts the report + leaked file (no server needed)", v.returncode == 0 and "VERIFIED" in v.stdout, v.stdout[-400:] + v.stderr[-300:])
    b = requests.get(f"{API}/cases/{case}/bundle", headers=H(sec)).json()
    b["bundle"]["finding"]["name"] = "Officer 3"
    json.dump(b, open(T("forged.json"), "w"))
    v = verifier(T("forged.json"))
    check("OFFLINE verifier catches an edited evidence file", v.returncode == 1 and "NOT VERIFIED" in v.stdout, v.stdout[-300:])
    j = trace(sec, img_id, T("iyer.png")).json()
    r = requests.post(f"{API}/cases/{j['case_id']}/decision", headers=H(adm), json={"approve": False, "note": "needs review"})
    check("a case can be rejected by the second person", r.status_code == 200 and r.json()["status"] == "REJECTED")
    check("a rejected case releases no evidence", requests.get(f"{API}/cases/{j['case_id']}/report", headers=H(sec)).status_code == 409)
    cs = requests.get(f"{API}/cases", headers=H(sec)).json()
    check("cases list shows confirmed + rejected cases", {"CONFIRMED", "REJECTED"} <= {c["status"] for c in cs})

    ex = requests.get(f"{API}/ledger/export", headers=H(sec))
    check("ledger export works for staff only", ex.status_code == 200 and requests.get(f"{API}/ledger/export", headers=H(rao)).status_code == 403)
    json.dump(ex.json(), open(T("ledger.json"), "w"))
    v = verifier(T("ledger.json"))
    check("OFFLINE verifier checks the whole exported chain", v.returncode == 0, v.stdout[-400:] + v.stderr[-300:])

    # ---------------------------------------------------------------- v5.1: protected viewer reports blocked screenshots
    r = requests.post(f"{API}/events/protect", headers=H(rao), json={"doc_id": img_id, "how": "PrintScreen key"})
    check("a blocked screenshot attempt is recorded", r.status_code == 200 and r.json().get("logged"), r.text)
    check("screenshot reports need a login", requests.post(f"{API}/events/protect", json={"doc_id": img_id}).status_code == 401)

    # ---------------------------------------------------------------- v5: insider early warning + audit chain
    al = requests.get(f"{API}/alerts", headers=H(sec)).json()
    kinds = {(a["kind"], a["username"]) for a in al["alerts"]}
    check("insider watch flags officer1's burst of openings", ("BURST", "officer1") in kinds, kinds)
    check("insider watch flags officer3's refused attempt", ("REFUSED", "officer3") in kinds, kinds)
    check("insider watch flags the ledger tampering", any(k == "TAMPER" for k, _ in kinds))
    check("insider watch flags the screenshot attempt", ("SCREENSHOT", "officer1") in kinds, kinds)
    check("insider watch flags the confirmed leak against officer1", ("LEAK", "officer1") in kinds, kinds)
    check("insider watch ranks people by risk", al["people"] and al["people"][0]["score"] > 0)
    v = requests.get(f"{API}/audit/verify", headers=H(sec)).json()
    check("the audit log's own hash chain verifies", v["ok"] and v["checked"] > 50, v)

    # ---------------------------------------------------------------- audit
    ev = requests.get(f"{API}/audit", headers=H(adm)).json()
    kinds = {e["kind"] for e in ev}
    check("audit log records LOGIN, LOGIN_FAILED, SHARE, OPEN, DENIED, TRACE, TAMPER",
          {"LOGIN", "SHARE", "OPEN", "DENIED", "TRACE", "TAMPER", "LOGIN_FAILED"} <= kinds, kinds)
    check("audit log records bose's refused attempt",
          any(e["kind"] == "DENIED" and e["username"] == "officer3" and e["doc_id"] == img_id for e in ev))

    # ---------------------------------------------------------------- restart survival is checked by run_10x.py
    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED: {FAILS}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
