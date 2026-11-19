# Security header cookbook

A safe baseline. Tighten the CSP to the origins the app really loads from, and test in report-only mode first if the app has inline scripts.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

Leave out `X-XSS-Protection`, or send `X-XSS-Protection: 0`. The filter it controls is gone from current browsers and caused leaks where it ran. Use `same-origin-allow-popups` for COOP if login or payment runs in a popup.

## Strict CSP with nonces

Host allow-lists are easy to bypass through JSONP endpoints and script gadgets on allowed CDNs. A nonce-based policy holds up better:

```
Content-Security-Policy: script-src 'nonce-{random per response}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'
```

Current browsers honor only the nonce and `'strict-dynamic'`; `https:` and `'unsafe-inline'` are fallbacks for old browsers and are ignored when a nonce is present. Generate a fresh nonce for every response, never reuse one. `header_audit.py` treats this pattern as strict (no HDR-012/014) and wants `base-uri` next to it (HDR-017).

## nginx

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
server_tokens off;
```

`add_header` in a `location` block replaces the ones from `server`, so repeat them or use an include file.

## Apache

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
ServerTokens Prod
ServerSignature Off
```

## Express

```js
import helmet from "helmet";
app.use(helmet());               // sensible defaults for all of the above
app.disable("x-powered-by");
```

## Next.js (`next.config.js`)

```js
async headers() {
  return [{ source: "/(.*)", headers: [
    { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  ]}];
}
```

Set the CSP with a nonce from middleware if the app uses inline scripts.

## Cloudflare

Rules > Transform Rules > Modify Response Header, add each header as "Set static". HSTS also lives under SSL/TLS > Edge Certificates.

## Cookies

```
Set-Cookie: __Host-session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax
```

The `__Host-` prefix makes the browser refuse the cookie unless it is Secure, has `Path=/` and no `Domain`, which blocks subdomain overwrites.

Get the prefix rules exactly right: a `__Host-` cookie with a `Domain` attribute or a path other than `/`, or a `__Secure-` cookie without `Secure`, is dropped by the browser without any error (`header_audit.py` CK-003).
