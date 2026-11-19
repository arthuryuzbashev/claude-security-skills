# TLS hardening baseline

A short, current baseline for public HTTPS servers and internal services. Use it to write fixes for `tls_check.py` findings.

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

Never: `NULL`, `EXPORT`, `RC4`, `DES`, `3DES`, `MD5`, anonymous (`ADH`, `AECDH`). Avoid plain RSA key exchange (`AES128-GCM-SHA256` without `ECDHE-` has no forward secrecy) and CBC suites where clients allow.

## Certificates

- Key: ECDSA P-256 (smaller, faster) or RSA 2048+ (3072 if it must last past 2030)
- Signature: SHA-256 or better. SHA-1 signed leaf certs are rejected by browsers
- Every served hostname in `subjectAltName`. Browsers ignore the CN
- Serve the full chain: leaf + intermediates, not the root. Missing intermediates work in some browsers (cached) and fail in curl, Java, Go and mobile apps
- Lifetime: publicly trusted TLS certs are capped by the CA/Browser Forum at 398 days (issued since 2020-09-01), stepping down under ballot SC-081 to 200 days (from 2026-03-15), 100 days (from 2027-03-15) and 47 days (from 2029-03-15). Automate renewal (ACME) and alert at 30 and 14 days left
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
```

### Caddy

Defaults are already TLS 1.2+ with modern suites and automatic certificates. Only pin explicitly if policy requires it:

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
| TLS-080..082 cipher | Use the cipher strings above |
