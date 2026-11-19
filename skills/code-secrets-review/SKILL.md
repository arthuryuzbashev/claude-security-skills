---
name: code-secrets-review
description: Find leaked secrets and risky code before they ship. Scans a repo or a diff for AWS, GitHub, Slack, Stripe, Google, SendGrid and npm keys, private key blocks, passwords in connection URLs, high-entropy secrets in config and committed .env files, always masked. Runs fast CWE-tagged static checks for Python, JavaScript/TypeScript, PHP and Go (eval, shell=True, pickle, unsafe yaml.load, SQL built from strings, innerHTML and dangerouslySetInnerHTML, disabled TLS checks, weak hashes, debug=True). Use whenever someone says "did I leak a key", "scan this repo for secrets", "pre-commit secret check", "security code review", "SAST", "is this code safe", "review this PR for security", "found an API key in git", or wants a CI gate for secrets or dangerous patterns.
---

# Code Secrets Review

Catch committed credentials and the classic injection and crypto mistakes, then tell the owner exactly what to rotate or change.

## When to use

- Before a commit, push, release or open-sourcing a repo: "did we leak anything?"
- A key showed up in git history, a log or a public paste
- Security pass on a PR or a whole codebase
- Adding a secrets or SAST gate to CI or a pre-commit hook

## Ground rules

- Never print a full secret. Both tools mask to the first 4 characters; keep it that way in reports, tickets and chat
- Never test whether a found key works (no API calls with it, no logins). Treat every real-looking secret as compromised and send it to its owner for rotation
- Deleting the line is not a fix: the secret stays in git history, forks, caches and CI logs. Rotate first, clean history second
- `sast_lite.py` reports patterns, not proven bugs. Read each hit and check whether untrusted input reaches it before calling it a vulnerability
- Only scan code you are allowed to review

## Workflow

1. Run `secret_scan.py <repo>` on the working tree. For a pending change, pipe the diff: `git diff --cached | secret_scan.py --stdin`
2. For each real-looking hit, find out whether it was ever committed or pushed (`git log -S '<first 4 chars>'` locally). If yes, it needs rotation, whatever the current file says. Follow `references/secret-response-runbook.md`
3. Suppress reviewed false positives: `secskills:ignore` on the line, or a path (optionally per rule) in `.secskills-ignore`. Note why in a comment
4. Run `sast_lite.py <repo>`. Triage high findings first: trace the input to each sink, mark it confirmed, not reachable, or false positive
5. For confirmed findings give the fix from the finding plus a code change. CWE meanings and safe replacements are in `references/sast-rules-cwe.md`
6. Wire both tools into CI with `--json --fail-on high` once the backlog is clean

## Tools

### secret_scan.py

```bash
python3 scripts/secret_scan.py examples/fake-repo
python3 scripts/secret_scan.py . --json --fail-on medium
git diff --cached | python3 scripts/secret_scan.py --stdin
```

- Skips `.git`, `node_modules`, virtualenvs, build output, binary files (NUL byte check), lockfiles, media and files over `--max-size` (1 MB)
- Rules: SEC-001 AWS access key id, SEC-002 AWS secret key, SEC-003 GitHub token, SEC-004 Slack token, SEC-005 Slack webhook, SEC-006 Stripe live key, SEC-007 Stripe test key (low), SEC-008 Google API key, SEC-009 private key block, SEC-010 password in a URL, SEC-011 SendGrid key, SEC-012 npm token
- SEC-020: a value with Shannon entropy at or above `--entropy` (3.5 bits/char) assigned to a secret-looking name (`password`, `token`, `api_key`, `client_secret`...). Quoted values everywhere; unquoted `NAME=value` lines only in non-code files (.env, .ini, shell). Placeholders like `changeme`, `<token>`, `${VAR}` are skipped
- SEC-030: an `.env` file in the tree (`.env.example`, `.sample`, `.template` are fine)
- AWS's documented example key (`...EXAMPLE`) is reported as info
- `.secskills-ignore` at the scan root: one glob per line (`tests/fixtures/*`), or `SEC-020:docs/*` for one rule. Inline `secskills:ignore` skips a line
- JSON: `target, files_scanned, findings`

### sast_lite.py

```bash
python3 scripts/sast_lite.py examples/fake-repo
python3 scripts/sast_lite.py src --lang py,js --json
python3 scripts/sast_lite.py --list-rules
```

- Python PY-001..009, JavaScript/TypeScript JS-001..007, PHP PHP-001..007, Go GO-001..005. Each finding has `cwe` and `language` keys on top of the standard ones; `detail` is the CWE plus the trimmed line
- Some rules have a built-in safe form that is not flagged: `yaml.load(..., Loader=SafeLoader)`, `usedforsecurity=False`, `htmlspecialchars(...)`, `unserialize(..., ['allowed_classes' => false])`
- Comment-only lines and lines with `secskills:ignore` are skipped
- Line-based: it misses data flow across lines and functions. Absence of findings is not proof of safety

Both tools: exit `1` when anything is at or above `--fail-on` (default `high`), `2` on bad input. Offline, read-only.

## Output

Lead with one line: files scanned, secrets found (by severity), code findings (by severity). Then two tables:

| Secret | Location | Masked value | Committed? | Action |
|---|---|---|---|---|

| Rule | CWE | Location | Reachable from input? | Fix |
|---|---|---|---|---|

End with what to rotate today, what to fix this sprint, and what was not covered (git history, binaries, other languages, cross-file data flow).

## References

- `references/secret-response-runbook.md` what to do when a secret leaks: rotate, investigate, clean history, prevent
- `references/sast-rules-cwe.md` every rule with its CWE, why it matters and the safe pattern
