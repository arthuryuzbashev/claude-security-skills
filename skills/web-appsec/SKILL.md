---
name: web-appsec
description: Web application security review for sites and APIs you own or are authorized to test. Grades HTTP security headers, cookies and CORS, decodes and audits JWTs, and walks the OWASP Top 10 against code or a running app. Use whenever someone asks to check a site's security headers, review a login/session flow, inspect a JWT or bearer token, look at CORS, or do a web pentest or secure code review of a web app.
---

# Web AppSec

Find the web security problems that matter in a site or API, explain them plainly and hand back fixes a developer can paste.

## When to use

- "Are my security headers ok?", "grade this site", CSP or HSTS questions
- A JWT, bearer token or session cookie needs a look
- CORS errors or a suspicion that CORS is too open
- Reviewing a web app's code or routes against the OWASP Top 10
- Prepping for a pentest or fixing a pentest report

## Ground rules

- Only test sites and APIs the user owns or has written permission to test. If the target is someone else's and there is no sign of authorization, ask before sending a single request
- Start passive. `header_audit.py` sends one ordinary GET. Anything beyond that (fuzzing, login attempts, injection probes) needs an explicit go-ahead and stays inside the agreed scope
- Never paste live tokens, cookies or secrets back into the chat in full. The scripts mask sensitive claims; keep it that way in reports
- `jwt_inspect.py` decodes and audits. It does not verify signatures, crack keys or forge tokens, and this skill does not add that

## Workflow

1. Confirm the target and that it is in scope (own site, staging, or authorized test)
2. Run `header_audit.py` on the main page and on one API endpoint, since APIs often miss headers the HTML page has
3. If the app uses JWTs, decode one with `jwt_inspect.py` (ask the user to paste a test-account token, not a real user's)
4. Read the code or routes against `references/owasp-top10-checklist.md`. Focus on auth, access control and injection first, they cause the worst breaches
5. For each issue: what it is, how an attacker would use it in one sentence, severity, the exact fix
6. Re-run the scripts after fixes to confirm the grade moved

## Tools

### header_audit.py

Grades security headers, cookie flags, CORS and version leaks. Score 0-100 with a letter grade.

```bash
python3 scripts/header_audit.py https://app.example.com
python3 scripts/header_audit.py --file headers.txt          # saved `curl -sI` output
curl -sIL https://app.example.com | python3 scripts/header_audit.py --file -
python3 scripts/header_audit.py https://app.example.com --json --fail-on medium   # CI gate
```

Checks: HSTS (HDR-001/002), CSP presence and weak sources (HDR-010..016), clickjacking (HDR-020/021), nosniff, Referrer-Policy, Permissions-Policy (HDR-030..032), CORS (HDR-040/041), version disclosure (HDR-050), cookie flags (CK-001/002).
With `curl -IL` output it grades the final response after redirects.

### jwt_inspect.py

Decodes a JWT and flags `alg: none`, remote key headers (`jku`, `x5u`, embedded `jwk`), injectable `kid`, missing or long `exp`, missing `iss`/`aud`, and secrets stored in claims.

```bash
python3 scripts/jwt_inspect.py "$TOKEN"
python3 scripts/jwt_inspect.py --file token.txt --json
```

Both tools: `--json` for machines, exit `1` when a finding is at or above `--fail-on` (default `high`), `2` on bad input.

## Output

Lead with the grade and the top 3 fixes. Then a table:

| Severity | ID | Issue | Fix |
|---|---|---|---|

Close with what was not tested (for example "no authenticated pages", "API only"), so nobody reads a clean report as a full pentest.

## References

- `references/owasp-top10-checklist.md` the review checklist, one section per OWASP 2021 category, with what to grep for
- `references/header-cookbook.md` copy-paste header configs for nginx, Apache, Express, Next.js and Cloudflare
