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
    r = requests.post(API + f"/open/{d['doc_id']}", headers=H(o1), json={"password": "officer1123"})
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
          requests.post(API + f"/open/{d['doc_id']}", headers=H(o2), json={"password": "officer2123"}).status_code == 403)
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
        rr = requests.post(API + f"/open/{d['doc_id']}", headers=H(o1), json={"password": "officer1123"})
        check("a modified ciphertext on disk is refused, not decrypted", rr.status_code == 500 and b"modified" in rr.content)

    # ---- v5: a stolen database alone is useless
    if db_path:
        import sqlite3
        import oqs
        from Crypto.Protocol.SecretSharing import Shamir
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        con = sqlite3.connect(db_path)
        rows = con.execute("SELECT idx, half1, half2 FROM shares WHERE doc_id=?", (d["doc_id"],)).fetchall()
        doc_row = con.execute("SELECT nonce, ct_path FROM documents WHERE doc_id=?", (d["doc_id"],)).fetchone()
        check("key shares in the database are sealed (not raw 16-byte Shamir shares)", rows and all(len(r[1]) != 16 for r in rows))
        broke = False
        try:
            h1 = Shamir.combine([(r[0], r[1][:16]) for r in rows[:3]])
            h2 = Shamir.combine([(r[0], r[2][:16]) for r in rows[:3]])
            AESGCM(h1 + h2).decrypt(doc_row[0], open(doc_row[1], "rb").read(), b"NISHAAN-v4")
            broke = True
        except Exception:
            pass
        check("a stolen database alone can NOT rebuild a document key (node key files needed)", not broke)
        users = con.execute("SELECT username, dsa_sk, keys_sealed FROM users").fetchall()
        check("no private key is stored unsealed", all(u[2] == 1 for u in users))
        forged = False
        try:
            oqs.Signature("ML-DSA-65", secret_key=users[0][1]).sign(b"forged receipt")
            forged = True
        except Exception:
            pass
        check("a private key copied from the database can NOT sign (sealed under the password)", not forged)

        # the audit log is hash-chained: a quiet edit is detected
        eid, detail = con.execute("SELECT id, detail FROM events ORDER BY id LIMIT 1 OFFSET 3").fetchone()
        con.execute("UPDATE events SET detail=? WHERE id=?", ("nothing happened here", eid))
        con.commit()
        v = requests.get(API + "/audit/verify", headers=H(adm)).json()
        check("a quietly edited audit-log entry is detected", not v["ok"] and v["first_bad_event"] == eid, v)
        con.execute("UPDATE events SET detail=? WHERE id=?", (detail, eid))
        con.commit()
        check("audit log verifies again once restored", requests.get(API + "/audit/verify", headers=H(adm)).json()["ok"])

        # v5.1: an insider deletes the newest ledger record straight from the database
        d2 = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                           files={"file": ("s2.png", open(os.path.join(TMP, "s.png"), "rb"), "image/png")}).json()
        requests.post(API + f"/open/{d2['doc_id']}", headers=H(o1), json={"password": "officer1123"})
        last = con.execute("SELECT idx FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
        con.execute("DELETE FROM blocks WHERE idx=?", (last[0],))
        con.commit()
        v = requests.get(API + "/ledger/verify", headers=H(adm)).json()
        check("a ledger record deleted straight from the database is caught by the node copies",
              not v["ok"] and any(b.get("deleted") and b["index"] == last[0] for b in v["blocks"]), v)
        v = requests.post(API + "/ledger/restore", headers=H(adm)).json()
        check("the deleted record is rebuilt from the node copies", v["ok"] and v["latest"] == last[0], v)
        con.close()

    # ---- v5: sign-to-open brute force, two-person rule, revocation bypass
    for _ in range(5):
        requests.post(API + f"/open/{d['doc_id']}", headers=H(o2), json={"password": "guess"})
    o3 = login("officer3").json()["token"]
    d3 = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer3"},
                       files={"file": ("s.png", open(os.path.join(TMP, "s.png"), "rb"), "image/png")}).json()
    for _ in range(5):
        requests.post(API + f"/open/{d3['doc_id']}", headers=H(o3), json={"password": "guess"})
    r = requests.post(API + f"/open/{d3['doc_id']}", headers=H(o3), json={"password": "officer3123"})
    check("guessing the password at sign-to-open locks the account", r.status_code == 429, r.status_code)
    sec = login("security").json()["token"]
    d4 = requests.post(API + "/documents", headers=H(adm), data={"recipients": "officer1"},
                       files={"file": ("s.png", open(os.path.join(TMP, "s.png"), "rb"), "image/png")}).json()
    r = requests.post(API + f"/open/{d4['doc_id']}", headers=H(o1), json={"password": "officer1123"})
    open(os.path.join(TMP, "o1b.png"), "wb").write(r.content)
    j = requests.post(API + "/trace", headers=H(sec), data={"doc_id": d4["doc_id"]},
                      files={"file": ("l.png", open(os.path.join(TMP, "o1b.png"), "rb"), "image/png")}).json()
    r = requests.post(API + f"/cases/{j['case_id']}/decision", headers=H(sec), json={"approve": True})
    check("two-person rule can't be bypassed by the same Security Officer", r.status_code == 403)
    check("evidence of an unconfirmed case can't be downloaded",
          requests.get(API + f"/cases/{j['case_id']}/bundle", headers=H(adm)).status_code == 409)
    check("an officer can't reach the evidence endpoints",
          requests.get(API + f"/cases/{j['case_id']}/report", headers=H(o1)).status_code == 403)
    requests.post(API + f"/documents/{d4['doc_id']}/access", headers=H(adm), json={"username": "officer1", "allow": False})
    r = requests.post(API + f"/open/{d4['doc_id']}", headers=H(o1), json={"password": "officer1123"})
    check("a revoked officer is refused even with a valid session and password", r.status_code == 403)
    r = requests.post(API + "/documents/" + d4["doc_id"] + "/access", headers=H(sec), json={"allow": False})
    check("the Security Officer can't withdraw documents (admin only)", r.status_code == 403)

    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED: {FAILS}")
        sys.exit(1)
    print("ALL SECURITY CHECKS PASSED")


if __name__ == "__main__":
    main()
