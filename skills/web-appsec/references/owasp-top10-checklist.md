# OWASP Top 10 (2021) review checklist

Use it to review code or a running app. Each section: what goes wrong, what to look at, what to grep for.

## A01 Broken access control

- Every route that reads or changes data checks that the current user owns that object, not just that they are logged in
- IDs in URLs or bodies (`/orders/1042`) cannot be swapped to reach someone else's data (IDOR)
- Admin routes check the role on the server, not by hiding buttons
- CORS does not reflect arbitrary origins with credentials
- Grep: `findById(req.params`, `where id =` without a user filter, `isAdmin` checks only in frontend code

## A02 Cryptographic failures

- HTTPS everywhere, HSTS on, no mixed content
- Passwords hashed with argon2id, scrypt or bcrypt (never MD5, SHA-1, plain SHA-256)
- No secrets in the repo, in JWT claims or in client bundles
- Grep: `md5(`, `sha1(`, `createHash('sha256').update(password`, `AES/ECB`, hard-coded keys

## A03 Injection

- SQL through parameterized queries or an ORM, never string concatenation
- No user input in shell commands, `eval`, template strings rendered server-side, or LDAP/XPath queries
- Output encoded for its context (HTML, attribute, JS, URL) to stop XSS
- Grep: `` `SELECT ... ${ `` , `"SELECT " +`, `exec(`, `child_process`, `os.system`, `subprocess(..., shell=True)`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `|safe`

## A04 Insecure design

- Rate limits on login, signup, password reset, OTP and any costly endpoint
- Password reset tokens single-use, short-lived, random
- Business rules (prices, quantities, balances) enforced server-side

## A05 Security misconfiguration

- Debug mode, stack traces and default admin pages off in production
- Security headers set (run `header_audit.py`)
- Directory listing off, `.git` and `.env` not served
- Cloud buckets private unless meant to be public

## A06 Vulnerable and outdated components

- Lockfiles committed, dependencies scanned (see the `vuln-triage` and `supply-chain` skills)
- Frameworks on supported versions

## A07 Identification and authentication failures

- MFA available for admin accounts
- Session ids rotated on login, invalidated on logout and password change
- Cookies `Secure; HttpOnly; SameSite`
- Generic login errors ("wrong email or password"), so emails cannot be enumerated
- JWTs: pinned algorithm, short `exp`, `iss`/`aud` checked (run `jwt_inspect.py`)

## A08 Software and data integrity failures

- No unsafe deserialization of user input (`pickle.loads`, Java `ObjectInputStream`, `yaml.load` without SafeLoader, `unserialize`)
- Third-party scripts loaded with Subresource Integrity or self-hosted
- CI/CD can't be modified by untrusted pull requests

## A09 Security logging and monitoring failures

- Logins, failed logins, permission denials and admin actions are logged with user id, IP and time
- Logs never contain passwords, tokens or full card numbers
- Someone gets alerted on spikes of failures

## A10 Server-side request forgery (SSRF)

- Any feature that fetches a user-supplied URL (webhooks, image import, link previews) blocks internal ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `::1`, `fc00::/7`
- Check the resolved IP after DNS, and again after redirects
- Grep: `requests.get(url`, `fetch(req.body.url`, `urlopen(`, `curl_exec`
