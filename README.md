# NISHAAN (निशान)

**Cryptographic attribution and immutable decryption provenance for multi-recipient encrypted document distribution.**
SIH 2026 · PS 26237 · Team -0 Degree

Every copy looks identical but carries an invisible mark tied to the exact opening (ledger record + session). Every opening is signed by the officer with a key sealed under their own password, voted on by a 4-of-5 node quorum, and chained on a tamper-evident ledger. If a document leaks, NISHAAN names the officer, a second officer confirms it, and NISHAAN issues a signed, court-ready evidence report that anyone can check offline.

---

## Start it

**Windows:** open *Ubuntu* (WSL), then:

```bash
cd /mnt/c/Users/<you>/Downloads/nishaan_mvp_v4
bash start.sh
```

**Linux/macOS:** `bash start.sh` from this folder.

**Air-gapped machine:** on a computer with internet and the same OS/Python, run `bash tools/make_offline_bundle.sh` once. It creates `offline_bundle/` (Python packages + the liboqs library). Copy the whole folder to the air-gapped machine and run `bash start.sh`: nothing is downloaded, no cloud service or public blockchain is used.

The first run installs everything it needs, which takes a few minutes. After that it starts in seconds. Then open **http://localhost:8000** in your browser. Keep the terminal open while you use it, and press Ctrl+C to stop.

## Demo accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Distribution Officer: shares documents, revokes access, traces leaks, manages people and nodes |
| `security` | `security123` | Security Officer: confirms or rejects leak findings (two-person rule), Insider watch, audit log |
| `officer1` … `officer10` | `officer1123` … `officer10123` (username + `123`) | Officers #01–#10: open documents shared with them |

The admin can add more officers under **People**. Each one gets their own post-quantum keys, sealed with their password, and their name and number are printed on every copy they open.

## The demo, step by step (≈ 7 minutes)

1. **admin → Share a document**: drop a PDF or photo, set *SECRET*, set the access window to *24 hours*, tick **Officer 1** and **Officer 2**, then press *Share document*.
2. Sign out, then **officer3** tries to open the document: **refused** (not a recipient), and the attempt is logged.
3. **officer1 → My documents → Open**: NISHAAN asks for the password (**sign to open**; the signing key is sealed with it). Try a wrong password first: refused. Then the right one: the 5 nodes vote (N5 is offline, so **4/5, quorum reached**), the block is sealed, 3 shares are released and the copy is marked. Download it.
4. **admin → Trace a leak**: drop Officer 1's downloaded copy. The result is **Officer 1, #01**, with the chance of a wrong match (**less than 1 in 10¹⁰⁰**) and the ledger record. A **case** opens: *awaiting confirmation*.
5. **admin → Leak cases**: admin *cannot* confirm their own trace (two-person rule). Sign in as **security → Leak cases → Confirm**. Now download the **Evidence report (PDF)**: a formal report with the hashes, ledger records, both approvals and the data for the Section 63 certificate (Bharatiya Sakshya Adhiniyam, 2023), with the signed evidence file attached inside.
6. Check the report **offline**: `python3 tools/verify_offline.py NISHAAN_evidence_C-0001.pdf leaked-copy.png` → *VERIFIED*.
7. **security → Insider watch**: early warnings such as after-hours openings, bursts of openings, refused attempts and the confirmed leak, with a risk ranking.
8. **admin → the document → Revoke** Officer 2, or **Withdraw from everyone**: the nodes now refuse to vote, even with the right password.
9. **admin → Ledger → Tamper**: rewrite block #1 to blame Officer 3, then **Verify**: **TAMPERED** at block #1. Then *Undo all tampering*.
10. **admin → Audit log → Verify audit log**: the audit log is hash-chained too.
11. **admin → Ledger nodes**: take N4 offline (only 3 left); now nothing opens. Bring it back.

Before the real demo, use **admin → Settings → Reset demonstration data** to start clean.

## What's real

| Piece | How |
|---|---|
| File encryption | AES-256-GCM, one random key per document |
| Key custody | Shamir 3-of-5: one share per ledger node. The server discards the key itself after splitting |
| Shares at rest | Each node's share is **sealed under that node's own key file** (`backend/.node_keys/N1.key` …). A stolen database alone cannot rebuild any key |
| "Sign to open" | Each officer has an **ML-DSA-65** (FIPS 204) key pair, **sealed with a key derived from their password** (scrypt + AES-256-GCM). The officer re-enters the password to sign each opening, so the server cannot sign on their behalf |
| Ledger quorum | 5 nodes, each with its own ML-DSA-65 key (sealed under its key file). A node votes only after checking the officer's signature **and the access policy** (still a recipient, not revoked, window open). 4 of 5 votes are needed |
| Chain | SHA3-256 block hashes, each block linked to the previous one. `Verify` re-checks every hash, link, officer signature and node vote |
| Key delivery | The rebuilt key is wrapped under the officer's **ML-KEM-768** (FIPS 203) public key |
| Access window + revoke | Optional expiry per document; revoke one officer or withdraw the whole document at any time; refused attempts are logged |
| Session watermark | Made at the moment of decryption: a DCT mark in the brightness channel of every page carrying **this opening's ledger record number** (1024 + block index), so every copy looks identical (PSNR ≈ 40–47 dB) but is forensically distinct, even two copies of the same officer. Survives resizing, JPEG re-saving, shrink + JPEG, single-page screenshots |
| Visible name (optional) | Off by default so copies look identical, as PS 26237 asks. The sender can switch on a visible deterrent (officer's name + footer band) per document |
| Protected viewer | In the document view, the copy is shown inside a protected viewer: it hides the page the moment the window loses focus (snipping tools, other apps) or a screenshot / print key is pressed (PrintScreen, Win+Shift+S, Cmd+Shift+3/4/5, Ctrl+P), wipes the clipboard after PrintScreen, blocks printing, right-click, copying and dragging, and logs each attempt to the audit log and Insider watch. Screen recording is not blocked |
| Text watermark | Zero-width-character tag with the same session mark in the PDF metadata. A second, independent trace path |
| Node copies of the ledger | Each of the 5 nodes keeps **its own copy** of the chain (`backend/node_ledgers/N1.db` …) and stores a block only after checking its hash and the 4-of-5 signatures itself. A record edited, inserted or **deleted** in the main ledger is caught by the node copies, and *Restore* rebuilds it from them. A node that was offline catches up when it comes back |
| Trace | Reads the session mark, looks the record up **in the node copies of the ledger**, and returns the exact decryption event (officer, time, session, signatures), with confidence and a **wrong-match probability** (Hoeffding bound over the 16 bits). Copies made by v5 (officer-number marks) still trace |
| Two-person rule | A trace opens a **case**. A *different* officer (admin ↔ security) must confirm it before any evidence is released |
| Evidence | Signed PDF report + JSON bundle (full blocks, every signature, every public key), signed by the NISHAAN evidence authority key (ML-DSA-65). **`tools/verify_offline.py`** checks it with no server and no network |
| Insider watch | Rule-based early warning: after-hours openings, bursts, refused attempts, failed sign-ins, tampering, confirmed leaks, with a per-person risk score |
| Audit | Every action logged, including refusals. The audit log is **hash-chained** and can be verified |
| Access control | JWT sessions. scrypt-hashed passwords. Lockout after 5 wrong tries (also at sign-to-open). Admin/security/officer roles. Automatic sign-out after 10 minutes idle |
| Persistence | SQLite. All keys persist, so the ledger still verifies after a restart. Older v4 databases are upgraded (and sealed) automatically |

## Honest limits (say these if judges ask)

- The 5 nodes run inside one process, not on 5 machines. Each has its own key file and its own copy of the ledger, but they sit on one computer here; in deployment each would be on separate hardware (ideally an HSM) under a different command.
- No web page can fully stop screenshots (a phone camera, or a capture tool that runs before the page notices). The protected viewer blocks and logs the common ways; a copy captured anyway still carries the invisible session mark and traces back.
- The session mark is 16 bits, so this prototype supports up to 64,511 openings; a longer code (with error correction) lifts this in the pilot.
- Officers' sealed keys are stored on the server and unsealed for a moment with their password. In deployment, signing and ML-KEM unwrapping would happen on the officer's smart card.
- The server rebuilds the original in memory from 3 shares to read the pixel mark back during tracing.
- Not built yet: tracing from a phone photo of a printed page, layout (line/word-shift) watermark, bait details, collusion-resistant (Tardos) codes, Reed–Solomon error correction.
- No HTTPS (runs on localhost). Demo passwords are simple on purpose. Change `NISHAAN_JWT_SECRET` and the seed passwords in `auth.py` for anything real.
- **Keep `backend/.node_keys/` safe**: without at least 3 node key files, stored documents can never be opened again. It is git-ignored on purpose.

## Security

See **[SECURITY.md](SECURITY.md)** for the full review: vulnerabilities found and fixed, 55 attack tests, and known limits.

## Tests

```bash
cd backend
python3 tests/run_10x.py
```

This runs **137 feature checks + 57 security (attack) checks, 10 times**, each on a fresh temporary database, followed by a restart-survival check every run. It never touches your real demo data. Stop your normal server first, since the test needs port 8000.

Last result: **10/10 runs passed (194 checks each).**

## Layout

```
nishaan_mvp_v4/
  start.sh                  one-command start
  frontend/index.html       the whole web console (served at http://localhost:8000)
  tools/verify_offline.py   checks evidence reports / ledger exports with no server
  backend/
    requirements.txt
    app/
      main.py               API routes, wires everything together
      auth.py               login, roles, lockout, password-sealed keys, sign-to-open
      crypto.py             AES-GCM, Shamir, ML-DSA-65, ML-KEM-768, SHA3, scrypt, sealing
      keystore.py           per-node key files (node keys + key shares sealed at rest)
      ledger.py             5-node quorum with policy checks, chain, verify, tamper demo
      evidence.py           signed evidence bundle + PDF report (Section 63 data)
      alerts.py             Insider watch early-warning rules
      watermark.py          pixel (DCT) + text (zero-width) marks, wrong-match bound
      pdf_support.py        PDF ↔ page images, metadata tag
      db.py                 SQLite, incl. hash-chained audit log
    tests/
      test_e2e.py           137 feature checks
      test_security.py      57 attack checks
      run_10x.py            10 fresh runs + restart checks
```

## Team split

- **Crypto + auth**: `crypto.py`, `auth.py`, `keystore.py`
- **Ledger + evidence**: `ledger.py`, `evidence.py`, `tools/verify_offline.py`
- **Watermark**: `watermark.py`, `pdf_support.py`. Spare time: test phone photos of printed pages
- **Frontend (2 people)**: `frontend/index.html` (formal navy console: left navigation panel, Times New Roman, light theme by default with a dark option). Edit it and press F5; no restart needed
- **Integration + video + submission**: `main.py`, `alerts.py`, README, demo script, GitHub, YouTube, final PPT slide

## API (for the curious)

`GET /health` · `POST /login` · `GET /me` · `GET /users` · `POST /users` · `GET /nodes` · `POST /nodes/toggle` · `POST /documents` · `GET /documents` · `POST /documents/{id}/access` · `POST /open/{id}` · `GET /ledger` · `GET /ledger/verify` · `GET /ledger/export` · `POST /ledger/tamper` · `POST /ledger/restore` · `POST /trace` · `GET /cases` · `POST /cases/{id}/decision` · `GET /cases/{id}/report` · `GET /cases/{id}/bundle` · `GET /alerts` · `GET /audit` · `GET /audit/verify` · `POST /admin/reset`. Interactive docs are at **http://localhost:8000/docs**.
