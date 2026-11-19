---
name: incident-response
description: Calm, structured incident response for systems the user owns or is responsible for. Builds a prioritized, read-only evidence and containment checklist (order of volatility) for ransomware, business email compromise, account takeover, web compromise, malware, data leaks, insider cases and lost devices on Linux, macOS and Windows, merges CSV, JSON lines, syslog, access logs and Windows event exports into one UTC timeline, and drafts the incident report. Use whenever someone says "we got hacked", "ransomware", "someone logged into my account", "our site was defaced", "weird process", "data leaked", "laptop stolen", asks what to do first, how to preserve evidence, how to build a timeline, or needs an incident report.
---

# Incident Response

Help the user get from "something is wrong" to a contained, documented incident without destroying the evidence they will need later.

## When to use

- An active or suspected incident: ransomware, phishing that worked, a taken-over account, a web shell, an EDR alert
- "What do I do first?" or "should I turn it off?"
- Building a timeline from logs pulled off several systems
- Writing the incident report, or a tabletop exercise for one of the eight incident types

## Ground rules

- Stay calm and keep it short. People in an incident need the next three actions, not an essay. Ask what is affected and whether it is still happening, then hand back the first steps
- Only on systems the user owns or is responsible for. Investigating someone else's systems or tracing an attacker back to their infrastructure is out of scope; point to law enforcement instead
- Evidence first, cleanup later. Do not power off, reboot, reimage, run AV "clean" or delete accounts until the volatile evidence is collected and the scope is known
- Everything the scripts suggest under evidence is read-only. Steps tagged `[APPROVAL]` change state (isolate, disable, revoke); the user decides and logs who approved them. Prefer reversible actions: disable, not delete
- Evidence goes to external media or a share, never the suspect disk, and every file collected gets a SHA-256 and a line in the evidence table
- All times in UTC. Record the original timezone of every log source
- Never echo credentials found in logs. `timeline_build.py` masks passwords, tokens and keys to their first 4 chars; keep that in reports
- Legal, insurance and notification decisions belong to people with authority. Flag the deadlines early (see `references/ir-playbook.md`), do not make the call

## Workflow

1. Triage in two questions: what kind of incident is it, and is damage still happening (encryption running, money moving, data flowing out)?
2. Run `triage_plan.py <type> --platform <os>` and give the user the first 3-5 steps. If damage is ongoing, containment comes first (the plan already orders it that way for ransomware, data leaks and lost devices)
3. Collect evidence in order of volatility: memory, network state, processes, sessions, then persistence and logs. Hash everything as it is collected
4. Export logs from every system involved and merge them with `timeline_build.py`. Look for the first malicious event (patient zero), lateral movement, and the attacker's accounts and IPs
5. Scope: list affected hosts, accounts and data, and what is still unknown. Re-run the timeline with `--keyword <ip|user>` for each indicator you find
6. Contain with approval, then eradicate (rebuild rather than clean) and recover from known-good backups
7. Fill in the report skeleton (`triage_plan.py <type> --report`) and close with lessons learned

## Tools

### triage_plan.py

Prints a numbered checklist for one incident type and platform: prepare, volatile evidence, type-specific evidence, containment, notification and recovery, each with why it matters and exact commands. Cloud and identity steps (Microsoft 365, Entra ID, Google Workspace, AWS) are included where the incident type needs them.

```bash
python3 scripts/triage_plan.py --list
python3 scripts/triage_plan.py ransomware --platform windows
python3 scripts/triage_plan.py bec --json
python3 scripts/triage_plan.py web-compromise --platform linux --report > incident-report.md
```

Types: `ransomware`, `bec`, `account-takeover`, `web-compromise`, `malware`, `data-leak`, `insider`, `lost-device`. Platforms: `linux`, `macos`, `windows`.
`--json` gives `{incident, platform, description, steps: [{priority, phase, title, why, commands, approval}]}`; with `--report`, `{incident, platform, report}`.
Commands contain placeholders like `<user>`, `<file>` and `user@example.test`; replace them before running. Evidence paths default to `/mnt/evidence`, `/Volumes/EVIDENCE`, `E:\evidence`.

### timeline_build.py

Merges any number of logs into one sorted UTC timeline. Detects the format per file:

- CSV/TSV with a time column (`timestamp`, `time`, `TimeCreated`, `@timestamp`, `eventTime`... or `--time-field`)
- JSON lines or a JSON array (CloudTrail `Records` files work as is)
- syslog (BSD `Mar  4 10:15:30 host ...` and RFC 5424), Apache/nginx access logs, any line starting with a timestamp

Timestamps: ISO 8601 with or without offset, epoch seconds/ms/us, Windows FILETIME, syslog without a year (`--year`), Windows/US `3/4/2026 10:15:30 AM` (`--dayfirst` for day-first locales), access-log `[04/Mar/2026:10:15:30 +0000]`. Naive timestamps are UTC unless `--tz-offset +04:00`.

```bash
python3 scripts/timeline_build.py examples/* --year 2026
python3 scripts/timeline_build.py auth.log access.log events.csv --keyword 203.0.113.45 --from 2026-03-04T09:00 --to 2026-03-04T12:00
python3 scripts/timeline_build.py *.jsonl --format csv --output timeline.csv
journalctl -o short-iso | python3 scripts/timeline_build.py - --keyword sshd
```

Output: markdown table (default), `--format csv` (`time_utc,source,host,message,raw_time`) or `--format json` (`{count, sources, skipped, events: [{time, epoch, source, host, message, raw_time}]}`). Lines without a readable timestamp are counted per file and reported on stderr, so nothing is dropped silently.

Both scripts: exit `0` on success, `2` on bad input or arguments. They read files only; `--output` is the one thing `timeline_build.py` writes.

## Output

During the incident: the next actions only, numbered, with commands, and which ones need approval.

Afterwards, the report in the skeleton's shape:

1. Summary (three sentences: what, impact, current state)
2. Timeline table in UTC, from patient zero to containment
3. Scope (hosts, accounts, data, still unknown)
4. Evidence table with SHA-256 and who collected it
5. IOCs, defanged (`hxxp://`, `203.0.113[.]45`)
6. Actions taken with approver, root cause, notifications, follow-ups with owners

Say plainly what was not checked (for example "no memory image", "logs only go back 7 days").

## References

- `references/ir-playbook.md` phases, severity levels, the first hour, communication rules and notification deadlines (GDPR, NIS2, SEC, HIPAA)
- `references/artifact-cheatsheet.md` where the evidence lives on Linux, macOS and Windows, plus the Windows event IDs and logon types worth knowing by heart
