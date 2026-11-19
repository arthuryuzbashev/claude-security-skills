---
name: web-appsec
description: Web application security review for sites and APIs you own or are authorized to test. Grades HTTP security headers (HSTS, CSP incl. nonce and strict-dynamic policies, COOP, clickjacking), cookies and cookie prefixes, CORS (wildcard, null origin) and version or source map leaks; decodes and audits JWTs (alg none, jku/x5u/jwk/x5c, kid injection, exp/iat); and walks the OWASP Top 10 2025 against code or a running app. Use whenever someone asks to check a site's security headers, grade a site, review a login or session flow, inspect a JWT or bearer token, debug or tighten CORS or CSP, map findings to OWASP 2025 (or translate old 2021 ids), or do a web pentest prep or secure code review of a web app.
---

# Web AppSec

Find the web security problems that matter in a site or API, explain them plainly and hand back fixes a developer can paste.

## When to use

- "Are my security headers ok?", "grade this site", CSP, HSTS or COOP questions
- A JWT, bearer token or session cookie needs a look
- CORS errors or a suspicion that CORS is too open
- Reviewing a web app's code or routes against the OWASP Top 10 (2025 edition)
- Prepping for a pentest or fixing a pentest report (including mapping 2021 category ids to 2025)

## Ground rules

- Only test sites and APIs the user owns or has written permission to test. If the target is someone else's and there is no sign of authorization, ask before sending a single request
- Start passive. `header_audit.py` sends one ordinary GET. Anything beyond that (fuzzing, login attempts, injection probes) needs an explicit go-ahead and stays inside the agreed scope
- Never paste live tokens, cookies or secrets back into the chat in full. The scripts mask sensitive claims; keep it that way in reports
- `jwt_inspect.py` decodes and audits. It does not verify signatures, crack keys or forge tokens, and this skill does not add that

## Workflow

Copy this checklist and tick it off:

```
- [ ] 1. Target confirmed in scope
- [ ] 2. header_audit.py on the main HTML page
- [ ] 3. header_audit.py on one API endpoint
- [ ] 4. jwt_inspect.py on a test-account token (if JWTs are used)
- [ ] 5. Code or routes reviewed against the OWASP 2025 checklist
- [ ] 6. Findings written up with fixes
- [ ] 7. Scripts re-run after fixes
```

1. Confirm the target and that it is in scope (own site, staging, or authorized test)
2. Run `header_audit.py` on the main page. Prefer `curl -sIL <url> | header_audit.py --file -` when redirects are involved, so the final response is graded
3. Run it again on one API endpoint, since APIs often miss headers the HTML page has. HTML-only checks (COOP) stay quiet on JSON responses
4. If the app uses JWTs, decode one with `jwt_inspect.py` (ask for a test-account token, not a real user's)
5. Read the code or routes against `references/owasp-top10-checklist.md`. Order: A01 access control (IDOR, SSRF), A07 authentication, A05 injection, then the rest. These cause the worst breaches
6. For each issue: what it is, how an attacker would use it in one sentence, severity, the exact fix (configs in `references/header-cookbook.md`)
7. Re-run the scripts after fixes and confirm the grade moved. If it did not, the header is probably set on the wrong layer (CDN vs app) or dropped by a nested nginx `location`

## Tools

### header_audit.py

Grades security headers, cookie flags, CORS and leaks. Score 0-100 with a letter grade (penalty per finding: critical 30, high 20, medium 10, low 4, info 0; A from 90, B 75, C 60, D 40).

```bash
python3 scripts/header_audit.py https://app.example.com
python3 scripts/header_audit.py --file headers.txt          # saved `curl -sI` output
curl -sIL https://app.example.com | python3 scripts/header_audit.py --file -
python3 scripts/header_audit.py https://app.example.com --json --fail-on medium   # CI gate
```

| Ids | Checks |
|---|---|
| HDR-001..003 | HSTS missing, short max-age, no includeSubDomains (info) |
| HDR-010..017 | CSP report-only, missing, `unsafe-inline` without nonce/hash, `unsafe-eval`, wildcard script sources (not flagged under nonce + `strict-dynamic`), no script/default-src, no object-src, nonce policy without `base-uri` |
| HDR-020/021 | Clickjacking: no frame-ancestors or X-Frame-Options, bad XFO value |
| HDR-030..034 | nosniff, Referrer-Policy, Permissions-Policy (info), `X-XSS-Protection: 1`, COOP missing on HTML (info) |
| HDR-040..042 | CORS `*` with credentials, `*` alone (info), `null` origin |
| HDR-050/052 | Version numbers in Server, X-Powered-By and similar; SourceMap header |
| CK-001..003 | Cookie Secure/HttpOnly/SameSite, SameSite=None without Secure, broken `__Host-`/`__Secure-` prefix |

`--http` with `--file` treats the response as plain HTTP (skips HSTS and Secure checks). `--insecure` skips TLS verification for self-signed test hosts. JSON keys: `target`, `status`, `score`, `grade`, `findings`.

### jwt_inspect.py

Decodes a JWT and audits header and claims.

```bash
python3 scripts/jwt_inspect.py "$TOKEN"            # "Bearer ..." prefix is fine
python3 scripts/jwt_inspect.py --file token.txt --json
```

| Ids | Checks |
|---|---|
| JWT-001/002 | Unsigned (`alg: none` or empty signature), symmetric HS* (info) |
| JWT-003..006 | `jku`/`x5u` remote keys, embedded `jwk`, `kid` with path or query characters, embedded `x5c` chain |
| JWT-010..014 | No `exp`, expired (info), lifetime over 7 days, no `iss`/`aud`, `iat`/`nbf` more than 5 minutes in the future |
| JWT-020 | Sensitive-looking claim names (password, secret, card...) |

JSON keys: `header`, `payload` (sensitive values masked to 4 chars), `signature_present`, `findings`. Encrypted tokens (JWE, 5 parts) are rejected with exit 2.

Both tools: exit `1` when a finding is at or above `--fail-on` (default `high`), `2` on bad input.

## Output

Lead with the grade and the top 3 fixes. Then a table:

| Severity | ID | OWASP 2025 | Issue | Fix |
|---|---|---|---|---|

Map script findings to OWASP: headers, cookies and CORS go to A02 (CORS that leaks user data also A01), JWT issues to A07, version leaks to A02. Close with what was not tested (for example "no authenticated pages", "API only"), so nobody reads a clean report as a full pentest.

## References

- `references/owasp-top10-checklist.md` review checklist per OWASP Top 10 2025 category with grep patterns, plus a 2021 to 2025 mapping table. Open it for any code review
- `references/header-cookbook.md` copy-paste header configs for nginx, Apache, Express, Next.js and Cloudflare, a strict nonce CSP and cookie prefix rules. Open it when writing fixes
