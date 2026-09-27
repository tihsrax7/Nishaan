# NISHAAN (निशान)

**Cryptographic attribution and immutable decryption provenance for multi-recipient encrypted document distribution.**
SIH 2026 · PS 26237 · Team 0dgree

Every copy carries its reader's invisible mark. Every opening is signed by the officer, voted on by a 4-of-5 node quorum, and chained on a tamper-evident ledger. If a document leaks, NISHAAN names the officer and shows the ledger record of when they opened it.

---

## Start it

**Windows:** open *Ubuntu* (WSL), then:

```bash
cd /mnt/c/Users/<you>/Downloads/nishaan_mvp_v4
bash start.sh
```

**Linux/macOS:** `bash start.sh` from this folder.

The first run installs everything it needs, which takes a few minutes. After that it starts in seconds. Then open **http://localhost:8000** in your browser. Keep the terminal open while you use it, and press Ctrl+C to stop.

## Demo accounts

| Username | Password | Who | Can |
|---|---|---|---|
| `admin` | `admin123` | Cdr. Mehta, Distribution Officer | share documents, trace leaks, control nodes, audit log, tamper demo, reset |
| `rao` | `rao123` | Lt. Cdr. Rao · #07 | open documents shared with him |
| `iyer` | `iyer123` | Cdr. Iyer · #11 | 〃 |
| `sharma` | `sharma123` | Lt. Sharma · #14 | 〃 |
| `fernandes` | `fernandes123` | Cdr. Fernandes · #19 | 〃 |
| `bose` | `bose123` | Lt. Cdr. Bose · #23 | 〃 |

On the sign-in page you can also click any row to fill it in.

## The demo, step by step (≈ 5 minutes)

1. **admin → Distribute**: drop a PDF or photo, set *SECRET*, tick **Rao** and **Iyer**, then press *Encrypt & distribute*. This shows the key split into 5 shares, with the key itself discarded.
2. Sign out, then **bose → Open document** and paste the ID. He's **refused**, because he's not a recipient, and the attempt is logged.
3. **rao → Inbox → Open**. Watch the 5 nodes vote: N5 is offline, so the result is **4/5, quorum reached**. The pipeline shows receipt signed, block sealed, 3 shares released, key delivered via ML-KEM, and the document marked. The copy comes back in full colour. Download it.
4. **rao → Ledger → Verify entire chain**: every block is shown as *Verified*.
5. **admin → Trace a leak**: pick the document and drop Rao's downloaded copy in. The result is **Lt. Cdr. Rao, #07**, with the ledger evidence. It still works if the copy is resized, screenshotted, or re-saved as JPEG.
6. **admin → Ledger → Tamper**: rewrite block #1 to blame Bose, then press **Verify**. The result is **TAMPERED** at block #1. Try *Edit + recompute its hash* too: it is still caught, because the node signatures and the next block's link break. Then press *Undo all tampering*.
7. **admin → Nodes**: take N4 offline (only 3 left). Now Rao can't open anything and **the file stays locked**. Bring N4 back online.
8. **admin → Audit log**: every login, share, open, refusal, trace and tamper is listed.

Before the real demo, use **admin → System → Reset demo data** to start clean.

## What's real

| Piece | How |
|---|---|
| File encryption | AES-256-GCM, one random key per document |
| Key custody | Shamir 3-of-5: one share per ledger node. The server discards the key itself after splitting |
| "Sign to open" | Each officer has an **ML-DSA-65** (FIPS 204) key pair and signs a receipt (doc, officer, session, time, ciphertext hash) |
| Ledger quorum | 5 nodes, each with its own ML-DSA-65 key. A node votes only after checking the officer's signature itself. 4 of 5 votes are needed |
| Chain | SHA3-256 block hashes, each block linked to the previous one. `Verify` re-checks every hash, link, officer signature and node vote |
| Key delivery | The rebuilt key is wrapped under the officer's **ML-KEM-768** (FIPS 203) public key |
| Pixel watermark | DCT mark in the brightness channel on every page. Keeps colour, is invisible (PSNR ≈ 40–47 dB), and survives resizing, JPEG re-saving, shrink + JPEG, single-page screenshots |
| Text watermark | Zero-width-character officer tag in the PDF metadata. A second, independent trace path |
| Trace | Majority vote across pages, a confidence score, both layers compared, and a match against the ledger |
| Access control | JWT sessions. scrypt-hashed passwords. Lockout after 5 wrong tries. Admin/officer roles. Recipient lists enforced |
| Audit | Every action logged, including refusals (non-recipient, failed quorum, failed login, tampering) |
| Persistence | SQLite. All keys persist, so the ledger still verifies after a restart |

## Honest limits (say these if judges ask)

- The 5 nodes run inside one process, not on 5 machines. Every signature and vote is real crypto, but it isn't networked yet.
- Officers' private keys are stored on the server, standing in for a smart card or officer device. In deployment, signing and ML-KEM unwrapping would happen on the officer's device.
- The server keeps a sealed reference copy of each original, which it needs to read the pixel mark back during tracing.
- Not built: layout (line/word-shift) watermark, bait details, collusion-resistant (Tardos) codes, Reed–Solomon error correction. These are in the design but not in this prototype.
- Demo passwords are simple on purpose. Change `NISHAAN_JWT_SECRET` and the seed passwords in `auth.py` for anything real.

## Tests

```bash
cd backend
python3 tests/run_10x.py
```

This runs **60 end-to-end checks, 10 times**, each on a fresh temporary database, followed by a restart-survival check every run. It never touches your real demo data. Stop your normal server first, since the test needs port 8000.

Last result: **10/10 runs passed.**

## Layout

```
nishaan_mvp_v4/
  start.sh                  one-command start
  frontend/index.html       the whole web console (served at http://localhost:8000)
  backend/
    requirements.txt
    app/
      main.py               API routes, wires everything together
      auth.py               login, roles, lockout, per-user keys
      crypto.py             AES-GCM, Shamir, ML-DSA-65, ML-KEM-768, SHA3, scrypt
      ledger.py             5-node quorum, chain, verify, tamper demo
      watermark.py          pixel (DCT) + text (zero-width) marks
      pdf_support.py        PDF ↔ page images, metadata tag
      db.py                 SQLite
    tests/
      test_e2e.py           60 checks
      run_10x.py            10 fresh runs + restart checks
```

## Team split

- **Crypto + auth**: `crypto.py`, `auth.py`
- **Ledger**: `ledger.py`
- **Watermark**: `watermark.py`, `pdf_support.py`. Spare time: test phone photos of printed pages
- **Frontend (2 people)**: `frontend/index.html`. Edit it and press F5; no restart needed
- **Integration + video + submission**: `main.py`, README, demo script, GitHub, YouTube, final PPT slide

## API (for the curious)

`GET /health` · `POST /login` · `GET /me` · `GET /users` · `GET /nodes` · `POST /nodes/toggle` · `POST /documents` · `GET /documents` · `POST /open/{id}` · `GET /ledger` · `GET /ledger/verify` · `POST /ledger/tamper` · `POST /ledger/restore` · `POST /trace` · `GET /audit` · `POST /admin/reset`. Interactive docs are at **http://localhost:8000/docs**.
