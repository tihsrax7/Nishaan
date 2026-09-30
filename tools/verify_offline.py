"""
NISHAAN offline verifier -- checks evidence WITHOUT the NISHAAN server and without any network.
Needs only Python 3 + liboqs-python (and pymupdf to read a PDF report).

    python3 tools/verify_offline.py NISHAAN_evidence_C-0001.pdf            # PDF report (bundle attached inside)
    python3 tools/verify_offline.py evidence.json                          # signed evidence bundle
    python3 tools/verify_offline.py evidence.json leaked_copy.png          # ...and check the leaked file's hash
    python3 tools/verify_offline.py ledger_export.json                     # the whole ledger chain

It re-computes every hash and re-checks every ML-DSA-65 signature (officer, all nodes, and the
evidence authority). Exit code 0 = everything verified, 1 = something does not match.
"""
import sys
import json
import hashlib

import oqs

ALG = "ML-DSA-65"
QUORUM = 4
GENESIS = "00" * 32
CORE = ["index", "prev_hash", "doc_id", "username", "officer_id", "session", "time", "receipt", "receipt_hash", "officer_sig"]
problems = []


def sha3(b):
    return hashlib.sha3_256(b).hexdigest()


def verify(msg, sig_hex, pub_hex):
    try:
        return bool(oqs.Signature(ALG).verify(msg, bytes.fromhex(sig_hex), bytes.fromhex(pub_hex)))
    except Exception:
        return False


def check(label, ok, detail=""):
    print(("  OK    " if ok else "  FAIL  ") + label + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        problems.append(label)


def check_block(b, officer_pubs, node_pubs):
    core = {k: b[k] for k in CORE}
    check(f"block #{b['index']}: sealed hash matches its contents", sha3(json.dumps(core, sort_keys=True).encode()) == b["block_hash"])
    check(f"block #{b['index']}: receipt matches its hash", sha3(json.dumps(b["receipt"], sort_keys=True).encode()) == b["receipt_hash"])
    check(f"block #{b['index']}: officer named in block = officer who signed",
          b["receipt"].get("username") == b["username"] and b["receipt"].get("officer_id") == b["officer_id"])
    pub = officer_pubs.get(b["receipt"].get("username"))
    check(f"block #{b['index']}: officer's ML-DSA-65 signature is valid", bool(pub) and verify(b["receipt_hash"].encode(), b["officer_sig"], pub))
    good = [n for n, s in b.get("votes", {}).items() if n in node_pubs and verify(b["block_hash"].encode(), s, node_pubs[n])]
    check(f"block #{b['index']}: {len(good)} valid node signatures ({', '.join(sorted(good))}), {QUORUM} needed", len(good) >= QUORUM)


def load(path):
    if path.lower().endswith(".pdf"):
        import pymupdf
        doc = pymupdf.open(path)
        if "nishaan-evidence.json" not in doc.embfile_names():
            raise SystemExit("this PDF has no attached NISHAAN evidence")
        data = doc.embfile_get("nishaan-evidence.json")
        doc.close()
        return json.loads(data)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    data = load(sys.argv[1])
    print(f"\nNISHAAN offline verification of {sys.argv[1]}\n")

    if "bundle" in data:                                           # ---- signed evidence bundle
        b = data["bundle"]
        digest = sha3(json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        print(f"Case {b['case']['case_id']}: '{b['document']['title']}' -> {b['finding']['name']} (#{b['finding']['officer_id']:02d})")
        print(f"Evidence authority key fingerprint: {sha3(bytes.fromhex(data['authority_public_key']))[:16]}\n")
        check("evidence has not been changed since it was signed (SHA3-256)", digest == data["bundle_sha3_256"])
        check("evidence authority's ML-DSA-65 signature is valid", verify(digest.encode(), data["signature"], data["authority_public_key"]))
        check("case was confirmed by a second person (two-person rule)",
              b["case"]["status"] == "CONFIRMED" and b["case"]["confirmed_by"] and b["case"]["confirmed_by"] != b["case"]["requested_by"])
        officer = b["public_keys"]["officer"]
        for blk in b["ledger_blocks"]:
            check(f"block #{blk['index']} is about this document and this officer",
                  blk["doc_id"] == b["document"]["doc_id"] and blk["username"] == b["finding"]["username"])
            check_block(blk, {officer["username"]: officer["ml_dsa_65"]}, b["public_keys"]["nodes"])
        check("at least one signed opening by this officer is on record", len(b["ledger_blocks"]) > 0)
        if len(sys.argv) > 2:
            h = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
            check("the leaked file given matches the one examined (SHA-256)", h == b["leaked_copy"]["sha256"], h)
    elif data.get("format") == "NISHAAN-ledger/1":                  # ---- whole ledger export
        prev = GENESIS
        print(f"{len(data['blocks'])} blocks\n")
        for blk in data["blocks"]:
            check(f"block #{blk['index']}: links to the previous block", blk["prev_hash"] == prev)
            check_block(blk, data["public_keys"]["officers"], data["public_keys"]["nodes"])
            prev = blk["block_hash"]
    else:
        raise SystemExit("not a NISHAAN evidence bundle or ledger export")

    print()
    if problems:
        print(f"NOT VERIFIED -- {len(problems)} check(s) failed.")
        sys.exit(1)
    print("VERIFIED -- every hash and signature checks out.")


if __name__ == "__main__":
    main()
