# NISHAAN: security review

Reviewed and tested on 30 Sep 2026 (v5.1). **Result: 194 automated checks (137 feature + 57 attack tests), run 10 times on fresh data, all passing.**

Run them yourself (stop the normal server first):

```bash
cd backend
python3 tests/run_10x.py
```

## v5.1: matching PS 26237 exactly

- **Copies look identical.** The visible name is now optional (off by default); only the invisible mark tells copies apart.
- **Mark per decryption session.** The invisible mark carries the ledger record number of that opening, so a leaked copy returns the exact decryption event, not just an officer.
- **Every node keeps its own copy of the ledger.** Deleting or editing a record in the main database is caught by the node copies and repaired from them (new attack test).
- **Protected viewer.** Screenshots (PrintScreen, Win+Shift+S, Cmd+Shift+3/4/5), printing, copying and right-click are blocked in the document view and each attempt is logged to Insider watch. Screen recording is allowed for now. A browser cannot stop every capture (e.g. a phone camera); anything captured still carries the invisible session mark.
- **Air-gapped install.** `tools/make_offline_bundle.sh` packs every dependency, including liboqs, so the target machine needs no internet.

## v5 hardening

| # | Problem a judge would raise | What v5 does |
|---|---|---|
| 8 | "Anyone who copies the database can decrypt every document" | Every node's key share and signing key is **sealed under that node's own key file** (`backend/.node_keys/`, owner-only, git-ignored). The database alone can't rebuild any key; tested by the attack suite |
| 9 | "The server could sign 'I opened it' for an officer" | Officers' private keys are **sealed under a key derived from their own password**. Each opening needs the password again (step-up), and the same 5-try lockout applies. A key copied from the database can't sign; tested |
| 10 | "An admin could frame an innocent officer" | **Two-person rule**: a trace only opens a case; a *different* officer must confirm it before any evidence is released. Self-confirmation is refused and logged |
| 11 | "Would this proof stand up in court?" | Signed evidence report (ML-DSA-65 evidence authority key) with SHA-256 / SHA3-256 hashes, full ledger records, both approvals and the Section 63 (BSA 2023) data; **offline verifier** included |
| 12 | "An insider could quietly edit the audit log" | The audit log is **hash-chained**; *Verify audit log* pinpoints the edited entry; tested |
| 13 | "What if an officer is transferred, or a document must be pulled back?" | **Access window + instant revoke**: the nodes check the policy before every vote, so a revoked or expired document can't be opened even with the right password |
| 14 | "What about an unattended screen?" | Automatic sign-out after 10 minutes without activity |

## Vulnerabilities found and fixed in the v4 review

| # | Severity | Problem | Fix |
|---|---|---|---|
| 1 | Critical | The token-signing secret was a fixed string in the source code, so anyone with the code could forge an **admin** login | Random 64-byte secret generated on first start, stored in `backend/.jwt_secret` (owner-only, git-ignored), or set via `NISHAAN_JWT_SECRET` (min 32 chars) |
| 2 | Critical | Role was read from the token, so a forged or edited token could escalate an officer to admin | Identity and role are now always loaded from the database on every request |
| 3 | High | CORS allowed any website (`*`) | Only `localhost:8000` / `127.0.0.1:8000`; extra origins must be listed in `NISHAAN_ALLOWED_ORIGINS` |
| 4 | High | A **plaintext** copy of every document was kept on disk for leak tracing | Removed. Only ciphertext is stored; tracing rebuilds the original **in memory** from the key shares |
| 5 | Medium | Secret documents and API data could be cached by the browser | `Cache-Control: no-store` on every response, plus `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, CSP `frame-ancestors 'none'` |
| 6 | Medium | Decompression bomb: a 157 KB image of 144 megapixels was accepted | Images over 60 MP, PDFs over 200 pages or with oversized pages, and uploads over 30 MB are refused. Uploads are read in chunks and stop at the limit |
| 7 | Low | Login time revealed whether a username exists | The password hash always runs, even for unknown users |

## What the attack tests try (all blocked)

- Forging admin tokens with guessed secrets; unsigned `alg=none` tokens; editing your own token to become admin or another officer
- Every admin-only endpoint called as an officer; every endpoint called with no login
- Cross-site requests from a foreign website
- Looking for plaintext documents or plaintext passwords on disk
- **Rebuilding a document key from a stolen database; signing with a private key copied from the database**
- **Quietly editing an audit-log entry**
- Opening another officer's document; seeing it in your list; **opening after access was revoked**
- **Guessing the password at sign-to-open (locks after 5); confirming your own leak case; downloading evidence of an unconfirmed case**
- Decompression bombs, oversized files, 205-page PDFs, corrupt PDFs, HTML/script in titles
- Path traversal and SQL-injection style IDs and usernames
- Password brute force (locks after 5 tries)
- Modifying a stored ciphertext on disk (detected and refused)
- Plus the feature suite: quorum refusal, ledger tamper detection (edit and edit + rehash), deactivated accounts, expiry, revocation, two-person rule, offline verification of real and forged evidence, restart survival

## Known limits (be upfront with judges)

1. **Single machine.** The 5 ledger nodes run in one process and their key files sit in one folder. Anyone with full control of the server machine could still rebuild keys. In deployment, each node runs on separate hardware (ideally an HSM) under a different administrator.
2. **Officer keys on the server, sealed.** They are unsealed for a moment with the officer's password. In deployment they live on each officer's smart card, and signing and ML-KEM unwrapping happen there.
3. **Demo endpoints.** Tamper / restore / reset exist for the demonstration. Start with `NISHAAN_DEMO=0` to disable them.
4. **No TLS.** It runs over plain HTTP on localhost. A network deployment needs HTTPS (reverse proxy) and a real certificate.
5. **Demo passwords.** The `admin123` / `officerN123` style passwords are for the demo only.
6. **Watermark.** It survives resizing, JPEG re-saving and screenshots, but a determined attacker who heavily crops, blurs, photographs a printout or re-types the content can defeat it. Collusion-resistant codes are in the design but not in this build.
7. **Key files are critical.** Losing `backend/.node_keys/` (3 or more node files) makes stored documents unrecoverable, by design.
