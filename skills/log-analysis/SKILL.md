---
name: log-analysis
description: Fast security triage of logs. Parses Linux auth.log / secure (sshd, sudo), nginx and apache access logs, and JSON lines, then flags SSH brute force, password spraying, logins that succeed after failures, unexpected sudo to root, web scanners, 404 bursts, probes for .env/.git/wp-admin, and SQL injection, XSS and path traversal in URLs, with top talkers. Also prints ready hunting queries in Splunk SPL, Microsoft KQL and Elastic ES|QL/EQL. Use whenever someone shares a log file or excerpt, asks "is someone attacking my server", "check my auth.log/access log", "who is brute forcing SSH", "what hit my site", or needs a Splunk, Sentinel/Defender or Elastic query for brute force, spraying, new admin users, encoded PowerShell, LSASS dumping and similar.
---

# Log Analysis

Get from a raw log to "what happened, from where, how bad, what to do" in minutes, and hand over queries so the same check runs in the SIEM next time.

## When to use

- Someone pastes or attaches auth.log, secure, an nginx/apache access log or a JSON log export
- "Is my server being brute forced?", "who is hammering my site?", "did anyone get in?"
- After an alert, to scope it: which IPs, which accounts, which time range
- Someone needs the same hunt in Splunk, Sentinel / Defender (KQL) or Elastic

## Ground rules

- Work on copies. Never edit, truncate or rotate the original logs; they may be evidence. Note the file name, size and time range you analysed
- Logs hold personal data (IPs, usernames, emails, sometimes tokens in URLs). Keep excerpts in the report short, and do not paste them into public tools
- `log_triage.py` masks secret-looking URL parameters (token, key, password, session...) to the first 4 chars. Do the same in anything you write by hand
- Detections here are heuristics. A WordPress admin hits `/wp-admin`, a pentest firm runs nuclei. Check the context before calling something an attack, and ask whether a scan was authorized
- Blocking IPs or locking accounts is the user's call. Recommend it, do not do it

## Workflow

1. Find out what the log is (host, service, timezone) and the question ("did anyone get in?" beats "anything weird?")
2. Run `log_triage.py` on the file. For JSON, map field names with `--field` if the defaults miss them (check `events_parsed` and `formats`)
3. Read findings from the top. `AUTH-003` (success after failures) and `WEB-007` (secret file served) come first, they mean possible compromise or exposure
4. Pivot on the worst source: every line from that IP, every action by that account after the suspicious login (`grep` the IP or user in the original file)
5. Tune thresholds if the result is noisy or empty (`--window`, `--brute-threshold`, `--spray-users`, `--notfound-threshold`), and say which values you used
6. If the user has a SIEM, give them the matching query from `query_translate.py` so the check covers all hosts and keeps running
7. Report with the shape below

## Tools

### log_triage.py

Auto-detects each line: syslog auth lines (classic `Nov 19 03:12:00 host sshd[123]:` and ISO-8601 timestamps), combined/common access logs, and JSON lines.

```bash
python3 scripts/log_triage.py /var/log/auth.log --year 2026
python3 scripts/log_triage.py examples/access.log
python3 scripts/log_triage.py examples/vpn_auth.jsonl --json
python3 scripts/log_triage.py events.jsonl --field ip=client.address --field user=actor.login --field outcome=result
zcat /var/log/auth.log.2.gz | python3 scripts/log_triage.py --file - --sudo-users alice,ops --fail-on medium
```

| ID | Severity | Detects | Default threshold |
|---|---|---|---|
| AUTH-001 | high | brute force: failures from one IP | 10 in 300s |
| AUTH-002 | high | password spray: distinct usernames from one IP | 5 in 300s |
| AUTH-003 | high / critical | success after failures from the same IP (critical if the IP also brute forced or the same account was tried) | 3 failures in the hour before |
| AUTH-004 | medium | sudo to root by a user not in `--sudo-users` | - |
| AUTH-005 | medium | denied sudo (not in sudoers, wrong password, command not allowed) | - |
| AUTH-006 | info | sudo to root summary when no `--sudo-users` given | - |
| WEB-001 | medium | scanner user agents (sqlmap, nikto, nuclei, wpscan, ffuf, gobuster...) | - |
| WEB-002 | medium | 404 burst from one IP | 20 in 60s |
| WEB-003 | medium | probes for sensitive paths (/.env, /.git, /wp-admin, /phpmyadmin, /server-status, backups) | - |
| WEB-004/005/006 | medium, high if any answer was 200 (004/006) | SQL injection, XSS, path traversal patterns in the decoded URL | - |
| WEB-007 | high | a secret-bearing file (.env, .git, keys, .sql/.bak dumps) answered 2xx | - |

JSON field defaults (first one present wins, dotted paths work): `ts` (@timestamp, timestamp, time), `ip` (source.ip, src_ip, client_ip, remote_addr), `user` (user.name, user, username), `outcome` (event.outcome, outcome, result), `path` (url.original, url.path, uri, path), `status`, `method`, `ua`. A JSON event with a path is treated as a web request; one with an outcome containing fail/deny/reject or success/accept/allow as a login.

`--json` keys: `source`, `events_parsed`, `skipped_lines`, `formats`, `time_range`, `findings` (id, severity, title, detail, fix, location), `top_talkers` (ip, events, auth_failed, auth_ok, web, errors_4xx_5xx). Exit `0` clean, `1` a finding at or above `--fail-on` (default `high`), `2` bad input or nothing parsed. Syslog lines carry no year; pass `--year` for old files (defaults to the current year, UTC assumed).

### query_translate.py

A library of hunting queries, each in Splunk SPL, Microsoft KQL and Elastic ES|QL, plus EQL where it fits. Every query states the data source and field names it assumes (Sysmon, Windows Security log, Defender `DeviceProcessEvents`, Sentinel `Syslog`/`SecurityEvent`, Elastic integrations).

```bash
python3 scripts/query_translate.py --list
python3 scripts/query_translate.py ssh-brute-force
python3 scripts/query_translate.py encoded-powershell --lang kql
python3 scripts/query_translate.py password-spray --threshold 20 --window 15 --json
```

Use cases: `ssh-brute-force`, `password-spray`, `new-admin-user`, `encoded-powershell`, `lsass-dump`, `office-child-process`, `scheduled-task`, `new-service`, `log-cleared`, `web-scanner`. `--threshold` and `--window` (minutes) fill the queries that count or bucket. EQL `with runs=` caps at 100. `--json` gives `use_case`, `title`, `attack`, `queries.{lang}.{query, source, available}`. Exit `0`, `2` for an unknown use case or no use case.

Index names (`index=sysmon`, `logs-system.auth-*`) are common defaults, not universal. Change them to the user's before running.

## Output

1. One line verdict: "brute force from 2 IPs, one login succeeded, treat `admin` as compromised" or "scanning only, nothing got through"
2. Scope: file, host, time range, events parsed, thresholds used
3. Findings table, worst first:

| Severity | ID | What | Source / account | Lines | Fix |
|---|---|---|---|---|---|

4. Top talkers (from the script) when they add context
5. Next steps: containment the user should decide on, the pivots still to do, and the SIEM query to keep watching
6. What was not covered (other hosts, other log files, time outside the file)

## References

- `references/log-sources.md` where each log lives, what the key auth.log and access log lines mean, Windows logon types and 4625 status codes, and a triage checklist
- `references/query-cheatsheet.md` the same operation side by side in SPL, KQL, ES|QL and EQL, with the pitfalls of each language
