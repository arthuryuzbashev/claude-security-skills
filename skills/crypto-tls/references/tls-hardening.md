# TLS hardening baseline

A short, current baseline for public HTTPS servers and internal services. Use it to write fixes for `tls_check.py` findings.
It follows Mozilla's Server Side TLS guidelines v6.0 ("intermediate" profile: TLS 1.2 + 1.3, ECDHE + AEAD only, no DHE; "modern" is TLS 1.3 only). Checked 2026-11-19.

## Protocols

| Version | Status | Action |
|---|---|---|
| SSL 2.0 / 3.0 | Broken (DROWN, POODLE) | Off |
| TLS 1.0 / 1.1 | Deprecated by RFC 8996 (2021), not allowed for PCI DSS | Off |
| TLS 1.2 | Fine with AEAD + ECDHE suites | On |
| TLS 1.3 | Preferred: only AEAD suites, always forward secret, faster handshake | On |

Only keep TLS 1.0/1.1 for a named legacy client, on a separate listener, with an end date.

## Cipher suites

TLS 1.3 (these three are all you need, the defaults in OpenSSL are fine):

```
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

TLS 1.2 (ECDHE key exchange + AEAD only):

```
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
```

Mozilla v6 dropped the DHE suites from intermediate: finite-field DH is slow and clients that lack ECDHE are gone.

Never: `NULL`, `EXPORT`, `RC4`, `DES`, `3DES`, `MD5`, anonymous (`ADH`, `AECDH`). Avoid plain RSA key exchange (`AES128-GCM-SHA256` without `ECDHE-` has no forward secrecy) and CBC suites where clients allow.

## Key exchange groups (post-quantum)

Mozilla v6 group order: `X25519MLKEM768:X25519:prime256v1:secp384r1`.

- `X25519MLKEM768` (codepoint 0x11EC) is a hybrid: X25519 plus ML-KEM-768 (FIPS 203). The session key stays safe if either half holds, so it protects recorded traffic against a future quantum computer ("harvest now, decrypt later") without trusting ML-KEM alone. Spec: RFC 10024 (2026); siblings `SecP256r1MLKEM768` (0x11EB) and `SecP384r1MLKEM1024` (0x11ED)
- Chrome, Firefox, Safari (iOS 26 / macOS 26), Cloudflare, Google and many CDNs offer it by default. OpenSSL 3.5+ and Go 1.24+ do too, so a server only needs a new enough library and a group list that does not shut it out
- The client key share is about 1.2 KB, so the ClientHello no longer fits one packet. Old middleboxes that drop split ClientHellos are the main breakage; test behind your load balancer
- Certificates and signatures stay classical for now (no ML-DSA certs in the Web PKI yet), so this only fixes the key exchange half
- `tls_check.py` reports the picked group as `key_exchange_group` and raises TLS-090 (info) when it is classical

## Certificates

- Key: ECDSA P-256 (smaller, faster) or RSA 2048+ (3072 if it must last past 2030)
- Signature: SHA-256 or better. SHA-1 signed leaf certs are rejected by browsers
- Every served hostname in `subjectAltName`. Browsers ignore the CN
- Serve the full chain: leaf + intermediates, not the root. Missing intermediates work in some browsers (cached) and fail in curl, Java, Go and mobile apps
- Lifetime: publicly trusted TLS certs are capped by the CA/Browser Forum at 398 days (issued since 2020-09-01), stepping down under ballot SC-081 (Baseline Requirements 2.3.1+) to 200 days (from 2026-03-15), 100 days (from 2027-03-15) and 47 days (from 2029-03-15). Domain validation reuse shrinks on the same dates, down to 10 days in 2029. Automate renewal (ACME, ideally with ARI renewal hints) and alert at 30 and 14 days left
- Revocation: Let's Encrypt removed OCSP URLs from new certificates on 2025-05-07 and turned its OCSP responders off on 2025-08-06; revocation is published through CRLs. OCSP stapling does nothing for those certs, and an nginx warning about a missing OCSP responder URL is harmless
- Wildcards: fine for many short-lived hosts, but the key ends up on many machines. Keep wildcard keys on the load balancer only
- Private keys: mode 0600, owned by the service user, never in git or container images

## HSTS and related headers

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

Add `preload` and submit to hstspreload.org only when every subdomain serves HTTPS. Removal from the preload list takes months.

## Server configs

### nginx

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;   # needs OpenSSL 3.5+
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_certificate     /etc/ssl/example/fullchain.pem;   # leaf + intermediates
ssl_certificate_key /etc/ssl/example/privkey.pem;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
```

### Apache httpd (mod_ssl)

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1:secp384r1
SSLHonorCipherOrder off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
```

### HAProxy

```
global
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-curves X25519MLKEM768:X25519:P-256:P-384
```

### Caddy

Defaults are already TLS 1.2+ with modern suites and automatic certificates, and builds on Go 1.24+ offer X25519MLKEM768 by default. Only pin explicitly if policy requires it:

```
tls {
    protocols tls1.2 tls1.3
}
```

### Client code

Clients should keep the platform defaults (they verify the chain and hostname). Point them at a private CA bundle instead of turning verification off. See `crypto-cheatsheet.md`.

## Manual checks with openssl

```bash
# what the server negotiates, and the chain it sends
openssl s_client -connect host.example.test:443 -servername host.example.test -showcerts </dev/null

# does it pick the post-quantum hybrid? (OpenSSL 3.5+; look for "Negotiated TLS1.3 group: X25519MLKEM768")
openssl s_client -connect host.example.test:443 -servername host.example.test -groups X25519MLKEM768:X25519 </dev/null

# does it still accept TLS 1.1? (needs a local OpenSSL that still has 1.1)
openssl s_client -connect host.example.test:443 -servername host.example.test -tls1_1 </dev/null

# read a cert
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in cert.pem -noout -text | grep -E "Signature Algorithm|Public-Key"

# chain verifies against a CA bundle?
openssl verify -CAfile ca-bundle.pem -untrusted intermediates.pem leaf.pem

# key matches cert? (the two outputs must be identical)
openssl x509 -in cert.pem -noout -pubkey | openssl sha256
openssl pkey -in key.pem -pubout | openssl sha256
```

Many recent OpenSSL builds have TLS 1.0/1.1 compiled out or blocked at the default security level. When `tls_check.py` reports "could not test", re-run from a host that still has them, or add `-cipher 'DEFAULT:@SECLEVEL=0'` to the `s_client` command where the build allows it.

## Finding to fix map

| Finding | Fix |
|---|---|
| TLS-001..003 expiry | Renew; set up ACME auto-renewal and expiry alerts |
| TLS-010/011 weak signature | Reissue with SHA-256 |
| TLS-020..022 weak key | New key (P-256 or RSA-2048+), reissue, revoke the old cert |
| TLS-030/032 untrusted | Public CA cert, or deploy the private root to every client; serve the full chain |
| TLS-040 name mismatch | Add the name to SAN, or fix SNI/vhost routing |
| TLS-060 long lifetime | Shorter certs plus automation |
| TLS-070..073 protocol | `ssl_protocols TLSv1.2 TLSv1.3` (or the equivalent above) |
| TLS-074 untested | Re-test 1.0/1.1 from a host whose OpenSSL still speaks them |
| TLS-080..082 cipher | Use the cipher strings above |
| TLS-090 no PQ hybrid | Upgrade to OpenSSL 3.5+ / Go 1.24+ and put `X25519MLKEM768` first in the group list |
