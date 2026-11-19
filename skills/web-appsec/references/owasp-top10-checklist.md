# OWASP Top 10 (2025) review checklist

Use it to review code or a running app. Each section: what goes wrong, what to look at, what to grep for.
Source: https://top10.owasp.org/2025/ (checked 2026-11-19). For a requirement-level audit use OWASP ASVS 5.0.0 (released 2025-05-30).

## Contents

- Mapping from the 2021 list
- A01 Broken Access Control (now includes SSRF)
- A02 Security Misconfiguration
- A03 Software Supply Chain Failures
- A04 Cryptographic Failures
- A05 Injection
- A06 Insecure Design
- A07 Authentication Failures
- A08 Software or Data Integrity Failures
- A09 Security Logging and Alerting Failures
- A10 Mishandling of Exceptional Conditions

## Mapping from the 2021 list

| 2025 | Was in 2021 |
|---|---|
| A01 Broken Access Control | A01, plus A10 SSRF folded in |
| A02 Security Misconfiguration | A05 |
| A03 Software Supply Chain Failures | A06 Vulnerable and Outdated Components, widened to builds and distribution |
| A04 Cryptographic Failures | A02 |
| A05 Injection (XSS included) | A03 |
| A06 Insecure Design | A04 |
| A07 Authentication Failures | A07 Identification and Authentication Failures |
| A08 Software or Data Integrity Failures | A08 |
| A09 Security Logging and Alerting Failures | A09 Logging and Monitoring |
| A10 Mishandling of Exceptional Conditions | new |

When a pentest report or ticket still uses 2021 ids, map them with this table instead of renumbering by hand.

## A01 Broken Access Control

- Every route that reads or changes data checks that the current user owns that object, not just that they are logged in
- IDs in URLs or bodies (`/orders/1042`) cannot be swapped to reach someone else's data (IDOR)
- Admin routes check the role on the server, not by hiding buttons
- CORS does not reflect arbitrary origins or allow `null` with credentials (`header_audit.py` HDR-040/042)
- SSRF: any feature that fetches a user-supplied URL (webhooks, image import, link previews, PDF renderers) blocks internal ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (cloud metadata), `::1`, `fc00::/7`. Check the resolved IP after DNS and again after every redirect
- Grep: `findById(req.params`, `where id =` without a user filter, `isAdmin` checks only in frontend code, `requests.get(url`, `fetch(req.body.url`, `urlopen(`, `curl_exec`

## A02 Security Misconfiguration

- Debug mode, stack traces and default admin pages off in production
- Security headers set (run `header_audit.py`), no `X-XSS-Protection: 1`, no source maps in production
- Directory listing off, `.git`, `.env` and backup files not served
- Cloud buckets private unless meant to be public; default credentials changed
- XML parsers have external entities off (XXE now lives here)
- Grep: `DEBUG = True`, `app.debug`, `autoindex on`, `Options +Indexes`, `resolve_entities`, `FEATURE_EXTERNAL`

## A03 Software Supply Chain Failures

- Lockfiles committed and installs reproducible (`npm ci`, `pip install --require-hashes`)
- Dependencies scanned for known CVEs (see the `vuln-triage` skill) and for typosquats or install hooks (see `supply-chain`)
- CI workflows pin actions to full commit SHAs and keep `GITHUB_TOKEN` read-only by default (`supply-chain` skill, `ci_audit.py`)
- Third-party scripts on pages load with Subresource Integrity or are self-hosted
- Frameworks and runtimes on supported versions

## A04 Cryptographic Failures

- HTTPS everywhere, HSTS on with includeSubDomains, no mixed content
- Passwords hashed with argon2id, scrypt or bcrypt (never MD5, SHA-1, plain SHA-256)
- No secrets in the repo, in JWT claims or in client bundles
- Random values for tokens come from a CSPRNG (`secrets`, `crypto.randomBytes`), not `Math.random` or `random`
- Grep: `md5(`, `sha1(`, `createHash('sha256').update(password`, `AES/ECB`, `Math.random()` near token code, hard-coded keys

## A05 Injection

- SQL through parameterized queries or an ORM, never string concatenation
- No user input in shell commands, `eval`, server-side templates, LDAP or XPath queries
- Output encoded for its context (HTML, attribute, JS, URL) to stop XSS; CSP as the second layer
- LLM features: user text never reaches a tool call, shell or SQL without validation
- Grep: `` `SELECT ... ${ `` , `"SELECT " +`, `exec(`, `child_process`, `os.system`, `subprocess(..., shell=True)`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `|safe`, `render_template_string(`

## A06 Insecure Design

- Rate limits on login, signup, password reset, OTP and any costly endpoint
- Password reset tokens single-use, short-lived, random
- Business rules (prices, quantities, balances, coupon use) enforced server-side and safe against races (two requests at once)
- Threat model written for payment, auth and file upload flows

## A07 Authentication Failures

- MFA available for admin accounts; passkeys or TOTP preferred over SMS
- Session ids rotated on login, invalidated on logout and password change
- Cookies `Secure; HttpOnly; SameSite`, ideally with the `__Host-` prefix
- Generic login errors ("wrong email or password"), so emails cannot be enumerated
- Breached-password check on signup and password change
- JWTs: pinned algorithm, short `exp`, `iss`/`aud` checked (run `jwt_inspect.py`)

## A08 Software or Data Integrity Failures

- No unsafe deserialization of user input (`pickle.loads`, Java `ObjectInputStream`, `yaml.load` without SafeLoader, PHP `unserialize`)
- Updates and plugins verified by signature before install
- Data that crosses a trust boundary (cookies, hidden fields, client state) is signed or kept server-side
- Grep: `pickle.loads`, `yaml.load(`, `unserialize(`, `ObjectInputStream`, `BinaryFormatter`

## A09 Security Logging and Alerting Failures

- Logins, failed logins, permission denials and admin actions are logged with user id, IP and time
- Logs never contain passwords, tokens or full card numbers
- Alerts fire on spikes of failures and someone is on the hook to read them; logging without alerting is the gap 2025 calls out
- Logs are append-only or shipped off the host, so an attacker cannot erase them

## A10 Mishandling of Exceptional Conditions

- Errors fail closed: an exception in an auth, payment or permission check denies the request instead of letting it through
- Return values and error results are checked (`err` ignored in Go, unchecked `fetch` status, swallowed `catch {}`)
- Error pages and API errors show a generic message and a request id, never stack traces, SQL or file paths
- Multi-step operations roll back fully on failure instead of resuming half-done
- Missing or malformed parameters are rejected up front; a global exception handler is the backstop, not the plan
- Grep: `except: pass`, `except Exception: pass`, `catch (e) {}`, `_ = err`, `if err != nil { }` with an empty body, `traceback.print_exc()` in responses, `res.send(err.stack)`, `DEBUG_PROPAGATE_EXCEPTIONS`
