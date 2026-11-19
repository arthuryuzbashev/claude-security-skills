---
name: crypto-tls
description: TLS and cryptography hygiene for servers and code you own or are authorized to assess. Checks a live TLS endpoint (protocol, cipher, TLS 1.0/1.1, post-quantum X25519MLKEM768 support, certificate expiry, CA/B Forum 200/100/47-day lifetime caps, SAN/hostname match, key size, SHA-1 signatures), parses PEM/DER certificates offline, scans source for weak crypto (fast hashes on passwords, low PBKDF2 iterations or bcrypt cost, ECB, static IVs, hard-coded keys, Math.random tokens, DES/3DES/RC4, RSA PKCS#1 v1.5 encryption, small RSA keys, verify=False, pinned TLS 1.0, JWT none) and identifies hash formats (bcrypt, argon2id, phpass, WordPress $wp$, LDAP {SSHA}, Django, NTLM-length) without cracking. Use whenever someone asks to check an SSL/TLS cert or HTTPS setup, "when does my cert expire", "is my server quantum-safe", reviews encryption or password hashing code, finds rejectUnauthorized false or InsecureSkipVerify, or pastes a hash and asks what it is.
---

# Crypto and TLS

Find weak TLS settings, unhealthy certificates and crypto mistakes in code, and hand back the exact fix.

## When to use

- "Check the TLS / SSL on this host", "is TLS 1.0 still on?", "when does the cert expire?", "do we have post-quantum TLS?"
- Planning for shorter certificate lifetimes (200 days from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15)
- A `.pem`, `.crt` or `.der` file to inspect before deploying or after a renewal
- Reviewing code that hashes passwords, encrypts data, makes tokens or calls HTTPS APIs
- Someone pastes a hash string and asks what format it is or whether it is safe for passwords
- Prepping for a PCI, SOC 2 or pentest finding about "weak ciphers" or "insecure crypto"

## Ground rules

- Only connect to hosts the user owns or is authorized to assess. `tls_check.py` does a few TLS handshakes and nothing else (no HTTP request, no cipher brute-force), but still ask when the target looks like someone else's
- Prefer offline first: a saved cert or a code checkout needs no network at all
- `crypto_review.py --hash-id` only names a format. This skill does not crack, look up or brute-force hashes, and does not help anyone do that. If the hash came from a breach dump that is not the user's own system, stop
- Never print keys, secrets or full hashes into the chat. The scripts mask them to the first 4 characters; keep that in reports
- A finding is a pattern match, not proof. Open the line and confirm it is reachable before calling it a vulnerability (MD5 for a cache key is fine)

## Workflow

1. Confirm the scope: which hosts/ports, which repo or files
2. Live endpoint: run `tls_check.py host[:port]`. If TLS 1.0/1.1 says "could not test", the local OpenSSL lacks them; say so, do not report "not supported". The key exchange line shows whether the server picked a post-quantum hybrid group
3. Cert file: run `tls_check.py --cert file.pem --hostname <the name it serves>`. Use `--now` to ask "will it still be valid on launch day?"
4. Code: run `crypto_review.py <repo or dir>`, then read each high/critical hit in context and drop false positives
5. Hashes: `crypto_review.py --hash-id <value>` to tell bcrypt from md5crypt from raw SHA-1, and recommend a migration path if storage is weak
6. Write fixes as config or code the user can paste. Use `references/tls-hardening.md` for server configs and `references/crypto-cheatsheet.md` for code replacements
7. Re-run after the fix to confirm the finding is gone

## Tools

### tls_check.py

Live: one verified handshake (plus one unverified to read the cert if verification fails), one pinned handshake each for TLS 1.0 and 1.1, and one raw TLS 1.3 ClientHello offering X25519MLKEM768 that stops at the ServerHello (no keys derived, works even when the local OpenSSL has no TLS 1.3). `--no-pq` skips it.
File: parses the first certificate in a PEM bundle or a DER file with a built-in ASN.1 reader.

```bash
python3 scripts/tls_check.py app.example.test
python3 scripts/tls_check.py app.example.test:8443 --no-legacy --no-pq --timeout 5
python3 scripts/tls_check.py --cert examples/legacy_wildcard.pem --hostname legacy.example.test
python3 scripts/tls_check.py --cert server.pem --now 2027-06-01 --json --fail-on medium
```

Checks: expiry (TLS-001..004), SHA-1/MD5 signature (TLS-010/011), RSA < 2048, DSA, weak EC curve (TLS-020..022), self-signed leaf, untrusted chain (TLS-030..032), hostname not covered (TLS-040), wildcard (TLS-050), validity over the CA/Browser Forum cap for its issue date, 398/200/100/47 days (TLS-060), no SAN (TLS-061), TLS 1.0/1.1 accepted or negotiated, no TLS 1.3 (TLS-070..073), legacy probe not possible (TLS-074), weak, non-forward-secret or CBC cipher (TLS-080..082), no post-quantum hybrid group picked (TLS-090, info).

JSON keys: `target`, `mode` (live/file), `chain_length`, `connection` (protocol, cipher, cipher_bits, verify_error, legacy, legacy_notes, plus key_exchange_group, pq_hybrid, pq_note when the PQ probe ran; null in file mode), `certificate` (subject, issuer, not_before, not_after, days_left, san_dns, san_ip, key_type, key_size, curve, signature_algorithm, self_signed, is_ca), `findings`.

### crypto_review.py

Scans source and config files (common extensions; `--all-files` for everything non-binary). Skips `node_modules`, `.git`, `vendor`, build dirs. A line containing `secskills-ignore` is skipped.

```bash
python3 scripts/crypto_review.py src/
python3 scripts/crypto_review.py examples/weak_app --json --fail-on critical
python3 scripts/crypto_review.py --hash-id '$2b$12$...'
python3 scripts/crypto_review.py --hash-id - < examples/hashes.txt
```

Rules: fast hash on a password (CRY-001), MD5 / SHA-1 in use (CRY-002/003), ECB (CRY-010, Java's `RSA/ECB/...` label is not flagged), static IV (CRY-011), RSA encryption with PKCS#1 v1.5 or no padding (CRY-012), hard-coded key (CRY-020), private key block (CRY-021), weak random for secrets (CRY-030), DES/RC4/RC2 (CRY-040), 3DES/Blowfish (CRY-041), small RSA/DSA/DH key (CRY-050), PBKDF2 under OWASP's iteration count, 600,000 for SHA-256, 220,000 for SHA-512, 1,400,000 for SHA-1 (CRY-051), bcrypt cost under 10 (CRY-052), TLS verification off (CRY-060), code or nginx config pinning SSL 3.0 / TLS 1.0 / 1.1 (CRY-061), JWT none (CRY-070), JWT verification off (CRY-071).

Scan JSON: `mode`, `files_scanned`, `findings` (each with `location` = `path:line` and a masked `evidence` line).
Hash-id JSON: `mode`, `results` with `input` (masked), `length`, `candidates`, `password_storage` (strong/ok/weak/unknown), `params` (cost, rounds, argon2 memory/iterations, PBKDF2 iterations and PRF, LDAP digest), `note`. Hash-id always exits 0 unless the input is empty.

Both tools: exit `0` clean, `1` a finding at or above `--fail-on` (default `high`), `2` bad input or connection failure.

## Output

Lead with one line: the endpoint grade or "N high/critical crypto issues in M files". Then:

| Severity | ID | Where | Issue | Fix |
|---|---|---|---|---|

For certs add expiry date and days left. For hashes add the format and whether it is fit for password storage.
Close with what was not covered (TLS 1.0/1.1 untested, PQ probe skipped, only one hostname checked, generated code or binaries not scanned).

## References

- `references/tls-hardening.md` Mozilla v6 baseline, post-quantum groups, certificate lifetime schedule, OCSP end, copy-paste nginx/Apache/HAProxy/Caddy config, `openssl` commands for manual checks
- `references/crypto-cheatsheet.md` what to use instead of each weak primitive, per language, OWASP password hashing parameters, RSA padding, IV/nonce rules and a hash format table
