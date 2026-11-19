---
name: log-analysis
description: Fast security triage of logs. Parses Linux auth.log / secure (sshd, sudo), nginx and apache access logs, AWS CloudTrail, Microsoft Entra ID sign-in logs and JSON lines, then flags brute force, password spraying, logins that succeed after failures, unexpected sudo to root, web scanners, 404 bursts, probes for .env/.git, SQL injection, XSS and path traversal, AWS root or no-MFA console sign-ins, CloudTrail logging turned off, new access keys, denied-call bursts, MFA fatigue and device code sign-ins. Also prints hunting queries in Splunk SPL, Microsoft KQL and Elastic ES|QL/EQL. Use whenever someone shares a log file, asks "is someone attacking my server", "check my auth.log/access log/CloudTrail/sign-in logs", "did anyone get in", or needs a Splunk, Sentinel/Defender or Elastic query for brute force, spraying, MFA fatigue, OAuth consent, encoded PowerShell, LSASS dumping and similar.
---

# Log Analysis

Get from a raw log to "what happened, from where, how bad, what to do" in minutes, and hand over queries so the same check runs in the SIEM next time.

## When to use

- Someone pastes or attaches auth.log, secure, an nginx/apache access log, CloudTrail records, an Entra ID sign-in export or a JSON log export
- "Was our AWS root account used?", "is someone spamming MFA prompts?", "who turned off CloudTrail?"
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
3. Read findings from the top. `AUTH-003` (success after failures), `WEB-007` (secret file served), `CLOUD-001` (root sign-in), `CLOUD-003` (trail stopped) and a critical `CLOUD-005` (MFA fatigue then success) come first, they mean possible compromise or exposure
4. Pivot on the worst source: every line from that IP, every action by that account after the suspicious login (`grep` the IP or user in the original file)
5. Tune thresholds if the result is noisy or empty (`--window`, `--brute-threshold`, `--spray-users`, `--notfound-threshold`), and say which values you used
6. If the user has a SIEM, give them the matching query from `query_translate.py` so the check covers all hosts and keeps running
7. Report with the shape below

## Tools

### log_triage.py

Auto-detects each line: syslog auth lines (classic `Nov 19 03:12:00 host sshd[123]:` and ISO-8601 timestamps), combined/common access logs, CloudTrail records (one per line, or a whole `{"Records": [...]}` file on one line), Entra ID sign-ins (Sentinel `SigninLogs` export, Graph `signIns` objects or a `{"value": [...]}` page, Azure diagnostic export) and generic JSON lines.

```bash
python3 scripts/log_triage.py /var/log/auth.log --year 2026
python3 scripts/log_triage.py examples/access.log
python3 scripts/log_triage.py examples/vpn_auth.jsonl --json
python3 scripts/log_triage.py examples/cloudtrail.jsonl
python3 scripts/log_triage.py examples/entra_signins.jsonl --mfa-threshold 5
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
| CLOUD-001 | high / critical | AWS root console sign-in succeeded (critical without MFA) | - |
| CLOUD-002 | medium | IAM user console sign-in without MFA | - |
| CLOUD-003 | high / medium | CloudTrail `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, event data store stop or delete (medium when the call failed) | - |
| CLOUD-004 | medium / low | `CreateAccessKey` / `CreateLoginProfile` / `UpdateLoginProfile` for another user (low for yourself) | - |
| CLOUD-005 | high / critical | Entra MFA fatigue: `500121` denials for one user (critical if a success follows) | 3 in 3600s (`--mfa-threshold`, `--mfa-window`) |
| CLOUD-006 | medium | Entra sign-in with the device code flow succeeded | - |
| CLOUD-007 | medium | burst of `AccessDenied` / `UnauthorizedOperation` from one AWS identity | 10 in `--window` (`--denied-threshold`) |

CloudTrail `ConsoleLogin` and Entra sign-ins also feed AUTH-001/002/003: Entra codes 50126, 50053, 50034, 50055, 50056 and 50057 count as failed logins, `0` as success, and MFA interrupts (50074, 50076) count as neither.

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

Use cases: `ssh-brute-force`, `password-spray`, `new-admin-user`, `encoded-powershell`, `lsass-dump`, `office-child-process`, `scheduled-task`, `new-service`, `log-cleared`, `web-scanner`, plus identity and cloud: `mfa-fatigue`, `oauth-consent`, `device-code-signin`, `entra-password-spray`, `aws-console-login-risk`, `cloudtrail-tampering`, `aws-access-key-created`. ATT&CK IDs follow v20 (`log-cleared` is T1685.005). `--threshold` and `--window` (minutes) fill the queries that count or bucket. EQL `with runs=` accepts 1 to 100; above that the EQL query is marked unavailable with a `note`. `--json` gives `use_case`, `title`, `attack`, `queries.{lang}.{query, source, available, note?}`. Exit `0`, `2` for an unknown use case or no use case.

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

- `references/log-sources.md` where each log lives, what the key auth.log and access log lines mean, Windows logon types and 4625 status codes, CloudTrail fields and the events that matter, Entra ID result codes and identity attack patterns, and a triage checklist
- `references/query-cheatsheet.md` the same operation side by side in SPL, KQL, ES|QL and EQL, the cloud and identity tables per SIEM, and the pitfalls of each language
