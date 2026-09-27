"""
NISHAAN security tests: tries to break in the way an attacker would.
Every check must PASS (= the attack is blocked). Run with the server already
running on a fresh database (tests/run_10x.py does this for you).
"""
import os
import sys
import time
import glob
import json
import base64
import tempfile

import warnings
import jwt
warnings.filterwarnings("ignore")
import requests
import numpy as np
import cv2
import pymupdf

API = os.environ.get("NISHAAN_API", "http://localhost:8000")
STORE = os.environ.get("NISHAAN_STORE")
TMP = tempfile.mkdtemp(prefix="nishaan_sec_")
FAILS = []


def check(name, cond, detail=""):
    ok = bool(cond)
    print(("PASS" if ok else "FAIL") + f" - {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def H(t):
    return {"Authorization": "Bearer " + t}


def login(u, p=None):
    return requests.post(API + "/login", json={"username": u, "password": p or f"{u}123"})


def colour_png(path, w=1200, h=900):
    img = np.zeros((h, w, 3), np.uint8)
    img[:] = (60, 140, 210)
    cv2.putText(img, "SECRET TEST PAGE", (60, 120), cv2.FONT_HERSHEY_SIMPLEX, 2, (20, 20, 20), 4)
    cv2.imwrite(path, img)


def main():
    adm = login("admin").json()["token"]
    o1 = login("officer1").json()["token"]
    o2 = login("officer2").json()["token"]
    colour_png(os.path.join(TMP, "s.png"))
    now = int(time.time())

    # ---- forged / tampered tokens
    for secret in ["nishaan-demo-secret-change-me", "secret", "admin", ""]:
        fake = jwt.encode({"sub": "admin", "username": "admin", "role": "admin", "officer_id": 0, "name": "x",
                           "iat": now, "exp": now + 3600}, secret or "x" * 32, algorithm="HS256")
        check(f"forged admin token (guessed secret '{secret or 'xxx…'}') is rejected",
              requests.get(API + "/audit", headers=H(fake)).status_code == 401)
    none = jwt.encode({"sub": "admin", "username": "admin", "role": "admin", "iat": now, "exp": now + 3600}, None, algorithm="none")
    check("unsigned 'alg=none' token is rejected", requests.get(API + "/audit", headers=H(none)).status_code == 401)
    head, body, sig = o1.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["role"] = "admin"
    body2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    check("officer editing their own token to role=admin is rejected",
          requests.get(API + "/audit", headers=H(f"{head}.{body2}.{sig}")).status_code == 401)
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["username"] = claims["sub"] = "officer2"
    body3 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    check("officer editing their token to impersonate another officer is rejected",
          requests.get(API + "/documents", headers=H(f"{head}.{body3}.{sig}")).status_code == 401)
    check("secret file is not hard-coded / not world-readable",
          not os.path.exists(os.environ.get("NISHAAN_SECRET_FILE", "")) or
          (os.stat(os.environ["NISHAAN_SECRET_FILE"]).st_mode & 0o077) == 0)

    # ---- role enforcement uses the database, not the token
    for path, method in [("/audit", "get"), ("/users", "post"), ("/nodes/toggle", "post"), ("/admin/reset", "post"),
                         ("/ledger/tamper", "post"), ("/ledger/restore", "post"), ("/documents", "post")]:
        r = getattr(requests, method)(API + path, headers=H(o1), json={})
        check(f"officer blocked from admin endpoint {method.upper()} {path}", r.status_code in (403, 422), r.status_code)
    for path, method in [("/documents", "get"), ("/ledger", "get"), ("/users", "get"), ("/nodes", "get"), ("/me", "get")]:
        check(f"anonymous blocked from {path}", getattr(requests, method)(API + path).status_code == 401)

    # ---- CORS: other websites can't use the API from a victim's browser
    r = requests.options(API + "/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    check("CORS does not allow a foreign website", r.headers.get("access-control-allow-origin") not in ("*", "https://evil.example"))
    r = requests.options(API + "/login", headers={"Origin": "http://localhost:8000", "Access-Control-Request-Method": "POST"})
    check("CORS still allows the console itself", r.headers.get("access-control-allow-origin") == "http://localhost:8000")

    # ---- no plaintext at rest
    d = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                      files={"file": ("s.png", open(os.path.join(TMP, "s.png"), "rb"), "image/png")}).json()
    if STORE:
        files = glob.glob(os.path.join(STORE, "*"))
        check("only ciphertext is stored on disk (no plaintext copy)", files and all(f.endswith(".ct") for f in files), files)
        orig = cv2.imencode(".png", cv2.imread(os.path.join(TMP, "s.png")))[1].tobytes()
        check("stored file does not contain the original bytes",
              all(orig[100:164] not in open(f, "rb").read() for f in files))
    db_path = os.environ.get("NISHAAN_DB")
    if db_path:
        blob = open(db_path, "rb").read()
        check("passwords are not stored in plain text", b"officer1123" not in blob and b"admin123" not in blob)

    # ---- tracing still works without the plaintext copy
    r = requests.post(API + f"/open/{d['doc_id']}", headers=H(o1))
    open(os.path.join(TMP, "o1.png"), "wb").write(r.content)
    j = requests.post(API + "/trace", headers=H(adm), data={"doc_id": d["doc_id"]},
                      files={"file": ("l.png", open(os.path.join(TMP, "o1.png"), "rb"), "image/png")}).json()
    check("trace still names officer #01 (reference rebuilt from ciphertext in memory)", j.get("officer_id") == 1, j)

    # ---- secret documents are never cached by the browser
    check("opened document is sent with Cache-Control: no-store", "no-store" in r.headers.get("cache-control", ""))
    check("responses carry nosniff + frame protection",
          r.headers.get("x-content-type-options") == "nosniff" and r.headers.get("x-frame-options") == "DENY")

    # ---- access control between officers
    check("officer2 cannot open a document shared only with officer1",
          requests.post(API + f"/open/{d['doc_id']}", headers=H(o2)).status_code == 403)
    check("officer2 does not even see it in their list",
          all(x["doc_id"] != d["doc_id"] for x in requests.get(API + "/documents", headers=H(o2)).json()))

    # ---- malicious uploads
    big = np.zeros((12000, 12000), np.uint8)
    r = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                      files={"file": ("bomb.png", cv2.imencode(".png", big)[1].tobytes(), "image/png")})
    check("decompression bomb image (144 megapixels in 157 KB) is refused", r.status_code in (400, 413), r.status_code)
    r = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                      files={"file": ("huge.bin", b"\0" * (31 * 1024 * 1024), "application/octet-stream")})
    check("upload over 30 MB is refused", r.status_code == 413, r.status_code)
    pd = pymupdf.open()
    for _ in range(205):
        pd.new_page()
    r = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                      files={"file": ("many.pdf", pd.tobytes(), "application/pdf")})
    check("PDF with too many pages is refused", r.status_code == 413, r.status_code)
    r = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                      files={"file": ("x.pdf", b"%PDF-1.4 garbage", "application/pdf")})
    check("corrupt PDF is refused cleanly (no crash)", r.status_code == 400, r.status_code)
    r = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1", "title": "<img src=x onerror=alert(1)>"},
                      files={"file": ("s.png", open(os.path.join(TMP, "s.png"), "rb"), "image/png")})
    check("HTML in a title is stored as plain text (the console escapes it)", r.json().get("title") == "<img src=x onerror=alert(1)>")

    # ---- injection / traversal in ids
    for bad in ["../../etc/passwd", "' OR '1'='1", "%00", "a" * 500]:
        rr = requests.post(API + "/open/" + requests.utils.quote(bad, safe=""), headers=H(o1))
        check(f"weird document id {bad[:18]!r} is handled safely", rr.status_code in (404, 422), rr.status_code)
    r = login("admin' --", "x")
    check("SQL-injection style username just fails to log in", r.status_code == 401)

    # ---- brute force + enumeration
    for _ in range(5):
        login("officer5", "wrong")
    check("5 wrong passwords lock the account", "locked" in login("officer5").text)
    t = []
    for u in ["officer6", "nobody_here"]:
        t0 = time.time()
        for _ in range(3):
            login(u, "wrongpass")
        t.append((time.time() - t0) / 3)
    check("login time does not reveal whether a username exists", abs(t[0] - t[1]) < 0.25 * max(t), [round(x * 1000) for x in t])

    # ---- ciphertext tampering on disk is detected
    if STORE:
        ct = glob.glob(os.path.join(STORE, d["doc_id"] + ".ct"))[0]
        data = bytearray(open(ct, "rb").read())
        data[50] ^= 1
        open(ct, "wb").write(bytes(data))
        rr = requests.post(API + f"/open/{d['doc_id']}", headers=H(o1))
        check("a modified ciphertext on disk is refused, not decrypted", rr.status_code == 500 and b"modified" in rr.content)

    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED: {FAILS}")
        sys.exit(1)
    print("ALL SECURITY CHECKS PASSED")


if __name__ == "__main__":
    main()
