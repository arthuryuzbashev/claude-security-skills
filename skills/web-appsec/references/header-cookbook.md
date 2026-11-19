# Security header cookbook

A safe baseline. Tighten the CSP to the origins the app really loads from, and test in report-only mode first if the app has inline scripts.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## nginx

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
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
