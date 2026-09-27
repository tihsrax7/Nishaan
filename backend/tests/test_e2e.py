"""
NISHAAN v4 end-to-end check. Plain script (not pytest): prints PASS/FAIL per check.
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

import requests
import pymupdf
import numpy as np
import cv2

API = os.environ.get("NISHAAN_API", "http://localhost:8000")
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


def share(tok, path, recipients, title="Test doc", cls="SECRET", mime=None):
    name = os.path.basename(path)
    return requests.post(f"{API}/documents", headers=H(tok),
                         data={"title": title, "classification": cls, "recipients": ",".join(recipients)},
                         files={"file": (name, open(path, "rb"), mime or "application/octet-stream")})


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
    r = login("rao")
    check("officer login works", r.status_code == 200 and r.json()["user"]["officer_id"] == 7)
    rao = r.json()["token"]
    iyer = login("iyer").json()["token"]
    bose = login("bose").json()["token"]
    check("wrong password rejected", login("rao", "nope").status_code == 401)
    check("unknown user rejected", login("ghost", "x").status_code == 401)
    for _ in range(5):
        login("sharma", "wrong")
    r = login("sharma")
    check("account locks after 5 wrong passwords", r.status_code == 401 and "locked" in r.text, r.text)
    check("no token -> 401", requests.get(f"{API}/documents").status_code == 401)
    check("garbage token -> 401", requests.get(f"{API}/documents", headers=H("garbage")).status_code == 401)
    r = requests.get(f"{API}/users", headers=H(rao))
    check("roster lists 6 users with key fingerprints",
          r.status_code == 200 and len(r.json()) == 6 and all(u["dsa_pub_fingerprint"] for u in r.json()))

    # ---------------------------------------------------------------- roles
    r = share(rao, T("colour.png"), ["rao"])
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
    check("share of a non-image/non-PDF rejected", share(adm, T("junk.bin"), ["rao"]).status_code == 400)

    # ---------------------------------------------------------------- image: share -> open -> trace
    r = share(adm, T("colour.png"), ["rao", "iyer"], title="Harbour photo", cls="SECRET", mime="image/png")
    check("admin shares an image to rao + iyer", r.status_code == 200, r.text)
    img_id = r.json()["doc_id"]
    check("share stores recipients + classification",
          r.json()["recipients"] == ["iyer", "rao"] and r.json()["classification"] == "SECRET")

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
    r = requests.post(f"{API}/open/{img_id}", headers=H(rao))
    t_open = time.time() - t0
    check("rao opens the image (4/5 quorum)", r.status_code == 200, r.text[:200])
    check("open is fast (< 3 s)", t_open < 3, f"{t_open:.1f}s")
    m = meta_of(r)
    check("meta: officer 7, 4 valid votes, N5 offline",
          m["officer_id"] == 7 and m["valid_votes"] == 4 and m["votes"]["N5"] == "offline", m)
    check("meta: key was delivered via ML-KEM-768 (1088-byte ciphertext)", m["kem_ciphertext_bytes"] == 1088)
    check("meta: download filename names the copy", m["filename"].endswith("__copy-07.png"), m["filename"])
    open(T("rao.png"), "wb").write(r.content)

    opened = cv2.imread(T("rao.png"), cv2.IMREAD_COLOR)
    orig = cv2.imread(T("colour.png"), cv2.IMREAD_COLOR)
    check("opened image keeps its colour", opened is not None and
          np.abs(opened[:, :, 0].astype(int) - opened[:, :, 2].astype(int)).mean() > 20)
    check("opened image looks identical (tiny change only)", np.abs(opened.astype(int) - orig.astype(int)).mean() < 2)

    r = trace(adm, img_id, T("rao.png"))
    j = r.json()
    check("trace names rao (#07)", r.status_code == 200 and j["found"] and j["officer_id"] == 7, j)
    check("trace has high confidence", j["layers"]["pixel_confidence"] > 0.8, j["layers"])
    check("trace links to rao's ledger block", len(j["ledger_blocks"]) == 1 and j["was_recipient"])

    small = cv2.resize(opened, (opened.shape[1] // 2, opened.shape[0] // 2))
    cv2.imwrite(T("leak_small.jpg"), small, [cv2.IMWRITE_JPEG_QUALITY, 75])
    j = trace(adm, img_id, T("leak_small.jpg")).json()
    check("trace survives shrink-to-half + JPEG-75", j.get("officer_id") == 7, j)

    r = requests.post(f"{API}/open/{img_id}", headers=H(iyer))
    open(T("iyer.png"), "wb").write(r.content)
    j = trace(adm, img_id, T("iyer.png")).json()
    check("iyer's copy traces to iyer (#11), not rao", j.get("officer_id") == 11, j)

    j = trace(adm, img_id, T("colour.png")).json()
    check("the unmarked original is NOT blamed on anyone", j["found"] is False, j)
    check("officer can NOT run a trace", trace(rao, img_id, T("rao.png")).status_code == 403)

    # ---------------------------------------------------------------- PDF
    r = share(adm, T("sample.pdf"), ["rao"], title="Movement order", cls="TOP SECRET", mime="application/pdf")
    check("admin shares a 2-page PDF", r.status_code == 200 and r.json()["pages"] == 2, r.text)
    pdf_id = r.json()["doc_id"]
    r = requests.post(f"{API}/open/{pdf_id}", headers=H(rao))
    check("rao opens the PDF", r.status_code == 200 and r.headers["content-type"] == "application/pdf")
    open(T("rao.pdf"), "wb").write(r.content)
    pd = pymupdf.open(T("rao.pdf"))
    check("opened PDF has 2 pages + our title", len(pd) == 2 and pd.metadata["title"] == "Movement order")
    px = pd[0].get_pixmap(clip=pymupdf.Rect(10, 720, 60, 780)).pixel(10, 10)
    check("opened PDF keeps colour (red band still red)", px[0] > 150 and px[1] < 90 and px[2] < 90, px)
    pd.close()
    j = trace(adm, pdf_id, T("rao.pdf"), "application/pdf").json()
    check("PDF trace: both layers name rao", j.get("officer_id") == 7 and j["layers"]["metadata"] == 7
          and j["layers"]["pixel"] == 7 and j["layers_agree"], j)

    # a single page screenshotted and saved as a JPEG
    pg = pymupdf.open(T("rao.pdf"))[1].get_pixmap(dpi=150)
    rgb = np.frombuffer(pg.samples, np.uint8).reshape(pg.height, pg.width, pg.n)[:, :, :3]
    cv2.imwrite(T("page2.jpg"), cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, 85])
    j = trace(adm, pdf_id, T("page2.jpg")).json()
    check("PDF trace from a single-page JPEG screenshot", j.get("officer_id") == 7, j)

    # metadata stripped -> pixel layer still works
    pd = pymupdf.open(T("rao.pdf"))
    pd.set_metadata({})
    pd.save(T("stripped.pdf"))
    pd.close()
    j = trace(adm, pdf_id, T("stripped.pdf"), "application/pdf").json()
    check("PDF trace survives stripped metadata (pixel layer)",
          j.get("officer_id") == 7 and j["layers"]["metadata"] is None, j)

    make_sample_pdf(T("big.pdf"), 30)
    big_id = share(adm, T("big.pdf"), ["rao"], mime="application/pdf").json()["doc_id"]
    t0 = time.time()
    r = requests.post(f"{API}/open/{big_id}", headers=H(rao))
    t_big = time.time() - t0
    check("30-page PDF opens in < 10 s", r.status_code == 200 and t_big < 10, f"{t_big:.1f}s")
    check("30-page PDF output < 15 MB", len(r.content) < 15_000_000, f"{len(r.content) // 1_000_000} MB")

    # ---------------------------------------------------------------- quorum
    set_nodes(adm, ["N4", "N5"])
    r = requests.post(f"{API}/open/{img_id}", headers=H(rao))
    check("with only 3 nodes online the file stays LOCKED (423)", r.status_code == 423, r.text)
    check("locked reply explains the vote", r.json().get("valid_votes") == 3)
    set_nodes(adm, [])
    r = requests.post(f"{API}/open/{img_id}", headers=H(rao))
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
    r = requests.post(f"{API}/ledger/tamper", headers=H(adm), json={"index": 2, "mode": "edit", "username": "bose"})
    v = r.json()["verify"]
    bad = [b["index"] for b in v["blocks"] if not b["ok"]]
    check("editing block #2 is detected at block #2", not v["ok"] and bad == [2], v)
    requests.post(f"{API}/ledger/restore", headers=H(adm))
    r = requests.post(f"{API}/ledger/tamper", headers=H(adm), json={"index": 2, "mode": "rehash", "username": "bose"})
    v = r.json()["verify"]
    bad = [b["index"] for b in v["blocks"] if not b["ok"]]
    check("edit + recomputed hash is STILL caught (votes + next link break)", not v["ok"] and 2 in bad and 3 in bad, v)
    v = requests.post(f"{API}/ledger/restore", headers=H(adm)).json()
    check("restore makes the chain verify clean again", v["ok"], v)

    # ---------------------------------------------------------------- audit
    ev = requests.get(f"{API}/audit", headers=H(adm)).json()
    kinds = {e["kind"] for e in ev}
    check("audit log records LOGIN, LOGIN_FAILED, SHARE, OPEN, DENIED, TRACE, TAMPER",
          {"LOGIN", "SHARE", "OPEN", "DENIED", "TRACE", "TAMPER", "LOGIN_FAILED"} <= kinds, kinds)
    check("audit log records bose's refused attempt",
          any(e["kind"] == "DENIED" and e["username"] == "bose" and e["doc_id"] == img_id for e in ev))

    # ---------------------------------------------------------------- restart survival is checked by run_10x.py
    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED: {FAILS}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
