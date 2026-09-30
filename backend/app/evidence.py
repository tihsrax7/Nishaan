"""
OWNER: Person B (ledger) / Person F (integration)
Court-ready evidence for a CONFIRMED leak case.

  bundle(case)      -> signed, machine-readable evidence (JSON). It carries the full ledger
                       blocks (officer + node signatures), every public key needed to check
                       them, the leaked file's hashes, the watermark analysis and both
                       approvals. Signed with the NISHAAN evidence authority's ML-DSA-65 key.
  report_pdf(case)  -> a formal PDF report for investigators and courts, with the signed
                       bundle attached inside it (nishaan-evidence.json), and the data needed
                       for the certificate under Section 63(4) of the Bharatiya Sakshya
                       Adhiniyam, 2023 (hash values, system, custody, who did what, when).

Both can be checked OFFLINE with tools/verify_offline.py (no server, no network).
"""
import json
import time
import datetime
import platform

import pymupdf

from . import crypto, db, keystore, ledger

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
ALG = crypto.SIG_ALG


def ist(t):
    return datetime.datetime.fromtimestamp(t, IST).strftime("%d %b %Y, %H:%M:%S IST") if t else "-"


# ---------------------------------------------------------------- evidence authority key
def authority():
    row = db.get_sys_key("authority")
    if row is None:
        pub, sk = crypto.new_sig_keypair()
        db.add_sys_key("authority", pub, crypto.seal(keystore.key("authority"), sk, "authority:dsa"))
        row = db.get_sys_key("authority")
    return row["pub"], crypto.unseal(keystore.key("authority"), row["sk"], "authority:dsa")


def authority_fingerprint():
    return crypto.sha3(authority()[0])[:16]


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---------------------------------------------------------------- bundle
def bundle(case_row, version: str) -> dict:
    doc = db.get_document(case_row["doc_id"])
    result = json.loads(case_row["result_json"])
    ev = result.get("event")
    if ev:                                  # session mark: the exact decryption record, as the nodes hold it
        blk, _ = ledger.lookup_block(ev["block_index"])
        blocks = [blk] if blk else []
    else:                                   # legacy officer mark: every opening of this document by them
        blocks = [json.loads(r["block_json"]) for r in db.find_blocks(case_row["doc_id"], case_row["officer_id"])]
    for b in blocks:
        b.pop("per_node", None)
    officer = db.get_user(case_row["username"])
    names = {u["username"]: u["name"] for u in db.list_users()}
    chain = ledger.verify_chain()
    body = {
        "format": "NISHAAN-evidence/1",
        "system": {"name": "NISHAAN", "version": version},
        "case": {"case_id": case_row["case_id"], "status": case_row["status"],
                 "requested_by": case_row["requested_by"], "requested_by_name": names.get(case_row["requested_by"]),
                 "requested_at": case_row["requested_at"],
                 "confirmed_by": case_row["decided_by"], "confirmed_by_name": names.get(case_row["decided_by"]),
                 "confirmed_at": case_row["decided_at"], "note": case_row["decision_note"] or ""},
        "document": {"doc_id": doc["doc_id"], "title": doc["title"], "classification": doc["classification"],
                     "doctype": doc["doctype"], "pages": doc["pages"], "shared_by": doc["created_by"],
                     "shared_at": doc["created_at"], "ciphertext_sha3_256": doc["ct_hash"],
                     "recipients": db.get_recipients(doc["doc_id"]) + db.get_revoked_recipients(doc["doc_id"])},
        "leaked_copy": {"file_name": case_row["leaked_name"], "size_bytes": case_row["leaked_size"],
                        "sha256": case_row["leaked_sha256"], "sha3_256": case_row["leaked_sha3"],
                        "examined_at": case_row["requested_at"]},
        "finding": {"officer_id": case_row["officer_id"], "username": case_row["username"],
                    "name": officer["name"] if officer else case_row["username"],
                    "was_recipient": result.get("was_recipient"), "layers": result.get("layers"),
                    "false_match_log10": result.get("false_match_log10"), "verdict": result.get("verdict"),
                    "decryption_event": ev},
        "ledger_blocks": blocks,
        "public_keys": {
            "officer": {"username": case_row["username"], "alg": ALG,
                        "ml_dsa_65": officer["dsa_pub"].hex() if officer else None},
            "nodes": {n["name"]: n["dsa_pub"].hex() for n in db.list_nodes()},
        },
        "chain_verification_at_export": {"ok": chain["ok"], "checked": chain["checked"],
                                         "bad_blocks": [b["index"] for b in chain["blocks"] if not b["ok"]]},
        "generated_at": time.time(),
    }
    pub, sk = authority()
    digest = crypto.sha3(canonical(body))
    return {"bundle": body, "bundle_sha3_256": digest, "signature_alg": ALG,
            "signature": crypto.sign(sk, digest.encode()).hex(),
            "authority_public_key": pub.hex(), "authority_fingerprint": crypto.sha3(pub)[:16]}


# ---------------------------------------------------------------- PDF report
class _Pdf:
    W, H, M = 595, 842, 56

    def __init__(self, footer):
        self.doc = pymupdf.open()
        self.footer = footer
        self._new()

    def _new(self):
        self.page = self.doc.new_page(width=self.W, height=self.H)
        self.y = self.M

    def _need(self, h):
        if self.y + h > self.H - self.M - 10:
            self._new()

    def _wrap(self, text, font, size, width):
        words, lines, cur = str(text).split(" "), [], ""
        for w in words:
            t = (cur + " " + w).strip()
            if pymupdf.get_text_length(t, fontname=font, fontsize=size) <= width or not cur:
                cur = t
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
        return lines

    def text(self, text, size=10.5, font="tiro", color=(0.08, 0.1, 0.16), indent=0, after=4, width=None):
        width = width or (self.W - 2 * self.M - indent)
        for ln in self._wrap(text, font, size, width):
            self._need(size * 1.4)
            self.page.insert_text((self.M + indent, self.y + size), ln, fontname=font, fontsize=size, color=color)
            self.y += size * 1.38
        self.y += after

    def rule(self, heavy=False):
        self._need(8)
        self.page.draw_line((self.M, self.y), (self.W - self.M, self.y), color=(0.08, 0.19, 0.42) if heavy else (0.75, 0.78, 0.84),
                            width=1.4 if heavy else 0.6)
        self.y += 8

    def heading(self, n, title):
        self._need(40)
        self.y += 6
        self.text(f"{n}.  {title.upper()}", size=10.5, font="tibo", color=(0.08, 0.19, 0.42), after=2)
        self.rule()

    def kv(self, label, value, lw=150):
        size = 10
        lines = self._wrap(value, "tiro", size, self.W - 2 * self.M - lw)
        self._need(size * 1.4 * len(lines) + 2)
        self.page.insert_text((self.M, self.y + size), label, fontname="tibo", fontsize=size - 0.5, color=(0.35, 0.4, 0.5))
        for ln in lines:
            self.page.insert_text((self.M + lw, self.y + size), ln, fontname="tiro", fontsize=size, color=(0.08, 0.1, 0.16))
            self.y += size * 1.38
        self.y += 3

    def finish(self):
        n = len(self.doc)
        for i, p in enumerate(self.doc):
            p.draw_line((self.M, self.H - 40), (self.W - self.M, self.H - 40), color=(0.75, 0.78, 0.84), width=0.6)
            p.insert_text((self.M, self.H - 26), self.footer, fontname="tiro", fontsize=8.5, color=(0.35, 0.4, 0.5))
            label = f"Page {i + 1} of {n}"
            p.insert_text((self.W - self.M - pymupdf.get_text_length(label, fontname="tiro", fontsize=8.5), self.H - 26),
                          label, fontname="tiro", fontsize=8.5, color=(0.35, 0.4, 0.5))


def _odds(log10p):
    if log10p is None:
        return "not computed"
    exp = int(-log10p)
    if exp >= 100:
        return "less than 1 in 10^100 (a coincidence is effectively impossible)"
    if exp >= 12:
        return f"less than 1 in 10^{exp}"
    return f"less than 1 in {10 ** exp:,}"


def report_pdf(case_row, version: str) -> bytes:
    ev = bundle(case_row, version)
    b = ev["bundle"]
    c, d, lk, f = b["case"], b["document"], b["leaked_copy"], b["finding"]
    L = f.get("layers") or {}
    pdf = _Pdf(f"NISHAAN  ·  Leak attribution report  ·  Case {c['case_id']}  ·  {d['classification']}")

    # title block
    p = pdf.page
    p.draw_rect(pymupdf.Rect(0, 0, pdf.W, 8), color=None, fill=(0.04, 0.11, 0.24))
    pdf.y = 44
    pdf.text("NISHAAN", size=11, font="tibo", color=(0.08, 0.19, 0.42), after=0)
    pdf.text("Leak Attribution Evidence Report", size=21, font="tibo", after=2)
    pdf.text(f"Case {c['case_id']}   ·   Document classification: {d['classification']}   ·   Generated {ist(b['generated_at'])}",
             size=10, color=(0.35, 0.4, 0.5), after=6)
    pdf.rule(heavy=True)

    pdf.heading(1, "Finding")
    evt = f.get("decryption_event")
    if evt:
        pdf.text(f"The leaked copy examined in this case carries the NISHAAN session mark of ledger record #{evt['block_index']}: "
                 f"the opening by {f['name']} (officer #{f['officer_id']:02d}, username '{f['username']}') on {ist(evt['time'])}, "
                 f"session {evt['session']}. That record is signed with the officer's own ML-DSA-65 key and approved by the "
                 f"ledger nodes. The finding was confirmed under the two-person rule.", size=11)
    else:
        pdf.text(f"The leaked copy examined in this case carries the NISHAAN mark of {f['name']} (officer #{f['officer_id']:02d}, "
                 f"username '{f['username']}'). The ledger holds {len(b['ledger_blocks'])} signed record(s) of this officer "
                 f"opening the document. The finding was confirmed under the two-person rule.", size=11)

    pdf.heading(2, "Document")
    pdf.kv("Title", d["title"])
    pdf.kv("Document ID", d["doc_id"])
    pdf.kv("Classification", d["classification"])
    pdf.kv("Shared by / on", f"{d['shared_by']}  ·  {ist(d['shared_at'])}")
    pdf.kv("Recipients", ", ".join(d["recipients"]))
    pdf.kv("Ciphertext SHA3-256", d["ciphertext_sha3_256"])

    pdf.heading(3, "Leaked copy examined")
    pdf.kv("File name", lk["file_name"])
    pdf.kv("Size", f"{lk['size_bytes']:,} bytes")
    pdf.kv("SHA-256", lk["sha256"])
    pdf.kv("SHA3-256", lk["sha3_256"])
    pdf.kv("Examined on", ist(lk["examined_at"]))

    pdf.heading(4, "Watermark analysis")
    pm = L.get("pixel_mark")
    pdf.kv("Invisible pixel mark", ("not readable" if L.get("pixel") is None else
                                    f"session mark {pm} -> ledger record #{pm - ledger.MARK_BASE} (officer #{L['pixel']:02d})"
                                    if pm is not None and pm >= ledger.MARK_BASE else f"officer #{L.get('pixel'):02d}"))
    pdf.kv("Mark strength", f"{round((L.get('pixel_confidence') or 0) * 100)}%  ·  {L.get('pages_agreeing', 0)} of {L.get('pages_checked', 0)} page(s) agree")
    pdf.kv("Metadata mark", f"officer #{L['metadata']:02d}" if L.get("metadata") is not None else "not present (image file or removed)")
    pdf.kv("Chance of a wrong match", _odds(f.get("false_match_log10")))
    pdf.text("Method: the number of the ledger record created at decryption is hidden as 16 bits, each repeated across many "
             "image blocks. For a copy without this mark every block vote is a coin flip; Hoeffding's inequality bounds the "
             "chance that all 16 bits come out this one-sided by accident.", size=9, color=(0.35, 0.4, 0.5))

    pdf.heading(5, "Ledger evidence")
    for blk in b["ledger_blocks"]:
        pdf.kv(f"Block #{blk['index']}", f"opened {ist(blk['time'])}  ·  session {blk['session']}  ·  "
                                         f"{blk.get('valid_votes', len(blk.get('votes', {})))} of 5 node signatures ({', '.join(sorted(blk.get('votes', {})))})")
        pdf.kv("   Block hash", blk["block_hash"])
    cv = b["chain_verification_at_export"]
    pdf.kv("Whole-chain check", ("VERIFIED - every hash, link, officer signature and node vote is valid"
                                 if cv["ok"] else f"PROBLEM at block(s) {cv['bad_blocks']}") + f"  ({cv['checked']} blocks checked)")

    pdf.heading(6, "Two-person authorisation")
    pdf.kv("Trace run by", f"{c['requested_by_name']} ({c['requested_by']})  ·  {ist(c['requested_at'])}")
    pdf.kv("Confirmed by", f"{c['confirmed_by_name']} ({c['confirmed_by']})  ·  {ist(c['confirmed_at'])}")
    if c.get("note"):
        pdf.kv("Note", c["note"])

    pdf.heading(7, "Integrity of this evidence")
    pdf.kv("Evidence SHA3-256", ev["bundle_sha3_256"])
    pdf.kv("Signed with", f"{ALG}  ·  NISHAAN evidence authority key {ev['authority_fingerprint']}")
    pdf.text("The complete machine-readable evidence -- full ledger blocks, every signature and every public key -- is "
             "attached to this PDF as 'nishaan-evidence.json'. Anyone can check it without the NISHAAN server or any "
             "network:  python3 tools/verify_offline.py <this-report>.pdf", size=9.5)

    pdf.heading(8, "Data for the certificate under Section 63(4), Bharatiya Sakshya Adhiniyam, 2023")
    pdf.kv("Electronic record", f"Leaked copy '{lk['file_name']}' and this report with its attached evidence file")
    pdf.kv("Produced by", f"NISHAAN {version} secure document distribution system, host '{platform.node() or 'server'}'")
    pdf.kv("Hash of leaked copy", f"SHA-256 {lk['sha256']}")
    pdf.kv("Hash of evidence", f"SHA3-256 {ev['bundle_sha3_256']}")
    pdf.kv("Operation", "All documents, openings and traces are recorded automatically; the ledger was verified "
                        "at the time of export (see section 5).")
    pdf.y += 18
    pdf.text("Signature of the person in charge: ______________________________      Date: ______________", size=10)
    pdf.text("Name / designation: ________________________________________________", size=10, after=2)
    pdf.text("This report supplies the details required for the certificate; the certificate itself must be signed by the "
             "responsible officer (Part A) and the expert (Part B) as prescribed.", size=8.5, color=(0.35, 0.4, 0.5))

    pdf.finish()
    pdf.doc.embfile_add("nishaan-evidence.json", json.dumps(ev, indent=1, ensure_ascii=False).encode(),
                        filename="nishaan-evidence.json", desc="Signed NISHAAN evidence bundle (verify offline)")
    pdf.doc.set_metadata({"title": f"NISHAAN leak attribution report {c['case_id']}", "producer": "NISHAAN",
                          "creator": "NISHAAN", "subject": f"Evidence SHA3-256 {ev['bundle_sha3_256']}"})
    out = pdf.doc.tobytes(garbage=3, deflate=True)
    pdf.doc.close()
    return out
