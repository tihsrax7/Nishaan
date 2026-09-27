# NISHAAN: security review

Reviewed and tested on 28 Sep 2026. **Result: 121 automated checks (78 feature + 43 attack tests), run 10 times on fresh data, all passing.**

Run them yourself (stop the normal server first):

```bash
cd backend
python3 tests/run_10x.py
```

## Vulnerabilities found and fixed in this review

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
- Opening another officer's document; seeing it in your list
- Decompression bombs, oversized files, 205-page PDFs, corrupt PDFs, HTML/script in titles
- Path traversal and SQL-injection style IDs and usernames
- Password brute force (locks after 5 tries)
- Modifying a stored ciphertext on disk (detected and refused)
- Plus the feature suite: quorum refusal, ledger tamper detection (edit and edit + rehash), deactivated accounts, restart survival

## Security design (what's real)

- **AES-256-GCM** file encryption; key split **Shamir 3-of-5**; the key itself is discarded after splitting
- **ML-DSA-65** (FIPS 204) signatures: officers sign every opening, and each node verifies the signature before co-signing
- **ML-KEM-768** (FIPS 203): the rebuilt key is wrapped to the officer's public key
- **SHA3-256** hash-chained ledger; `Verify` re-checks every hash, link, officer signature and node vote
- **scrypt** password hashing; lockout after 5 wrong passwords; 8-hour sessions; deactivated accounts cut off immediately
- Parameterised SQL everywhere; filenames sanitised; output escaped in the console
- Server listens on `127.0.0.1` only

## Known limits (be upfront with judges)

1. **Single machine.** The 5 ledger nodes run in one process, and their shares and keys sit in one database. Anyone with full access to the server machine could rebuild keys. In deployment, each node would run on separate hardware (ideally an HSM) under a different administrator.
2. **Officer keys held by the server.** Officers' private keys are stored server-side and used on their behalf. In deployment they would live on each officer's smart card or device, and signing and ML-KEM unwrapping would happen there.
3. **Demo endpoints.** Tamper / restore / reset exist for the demonstration. Start with `NISHAAN_DEMO=0` to disable them.
4. **No TLS.** It runs over plain HTTP on localhost. A network deployment needs HTTPS (reverse proxy) and a real certificate.
5. **Demo passwords.** The `admin123` / `officerN123` style passwords are for the demo only.
6. **Watermark.** It survives resizing, JPEG re-saving and screenshots, but a determined attacker who heavily crops, blurs or re-types the content can defeat it. Collusion-resistant codes are in the design but not in this build.
