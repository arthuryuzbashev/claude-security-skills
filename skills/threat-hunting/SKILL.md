---
name: threat-hunting
description: Hypothesis-driven threat hunting and incident triage. Pulls IOCs (IPs, domains, URLs, emails, MD5/SHA1/SHA256 hashes, CVEs, file paths, registry keys) out of reports, emails and logs, refangs or defangs them, and maps behaviour notes or detection names to MITRE ATT&CK techniques with per-tactic coverage and an ATT&CK Navigator layer. Use whenever someone pastes a threat report, phishing email, IR notes or alert list, asks "what IOCs are in this", "defang these", "map this to ATT&CK", "which techniques does this cover", wants a hunt plan or hypothesis, or needs a Navigator layer.
---

# Threat Hunting

Turn a hunch, a report or a pile of notes into a scoped hunt: indicators to search for, ATT&CK techniques to cover, and a clear record of what was looked at and what was found.

## When to use

- A threat intel report, vendor advisory or phishing email needs its IOCs pulled out and cleaned up
- Someone wants indicators defanged for a ticket or refanged for a blocklist
- IR or analyst notes need mapping to ATT&CK, or a coverage view per tactic
- Planning a hunt: "are we hit by X", "do we see technique Y anywhere", "build a hunt from this report"
- Building an ATT&CK Navigator layer for a report or a detection set

## Ground rules

- Hunt only in data the user is allowed to query (their own SIEM, EDR, logs). Do not look up internal hostnames or users in public services
- IOCs are leads, not verdicts. A hit on an IP or domain needs context (time, host, process) before anyone calls it a compromise
- Share defanged indicators in chat, tickets and email (`--defang`). Only refang for tooling that needs the real value (blocklists, SIEM lookups)
- Do not submit customer files or internal data to public sandboxes or VirusTotal without the user's OK. Hash lookups are fine, uploads are not
- The ATT&CK table in `attack_mapper.py` is a curated subset. No match means "not in the table", and any ID the script did not produce must be checked on attack.mitre.org before it goes in a report
- Mask secrets: URLs with token, key or password parameters are shortened to the first 4 chars by the scripts. Keep it that way

## Workflow

1. Write the hypothesis in one sentence: who or what, which behaviour, where it would show up. Example: "An attacker who phished a user ran encoded PowerShell from Office on a workstation in the last 14 days"
2. Gather the inputs: the report, email, alert export or notes. Run `ioc_extract.py` on them to get a clean, de-duplicated indicator list
3. Run `attack_mapper.py` on the behaviour notes. Use the techniques to pick data sources (`references/hunt-playbook.md` lists which log proves which technique)
4. Search: indicators first (fast, cheap), then behaviour (slower, finds what IOCs miss). For queries, use the log-analysis skill's `query_translate.py` if it is installed, or the hunt playbook patterns
5. For each hit: host, user, process tree, first and last seen, and whether it explains the hypothesis
6. Conclude: confirmed, refuted, or inconclusive (with the data gap that blocked you). A refuted hunt is a result, record it
7. Hand off: new detections for what you found (detection-engineering skill), blocklist entries (refanged), and the gaps in logging

## Tools

### ioc_extract.py

Extracts IPv4, IPv6, domains, URLs, emails, MD5/SHA1/SHA256, CVE IDs, Windows and Unix file paths, and registry keys. Handles defanged input (`hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[at]`, `[:]`). Drops private, loopback, link-local, multicast and CGNAT IPs and well-known benign domains (microsoft.com, google.com, mitre.org and so on) unless `--keep-all`. Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are kept so training data and examples work. File names like `invoice.docm` are not reported as domains.

```bash
python3 scripts/ioc_extract.py examples/incident_report.txt
python3 scripts/ioc_extract.py report.txt --format csv --defang       # for a ticket
python3 scripts/ioc_extract.py report.txt --format list --types ipv4,domain   # for a blocklist
cat email.eml | python3 scripts/ioc_extract.py --file - --json
```

Formats: `text` (grouped, default), `list` (one value per line), `csv` (`type,value`), `json` (`{"ipv4": [...], "domain": [...], ...}`, keys in a fixed order: ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve, filepath, registry). Exit `0` on success, even with no indicators, `2` on bad input or unknown `--types`.

### attack_mapper.py

Maps free text (one observation or detection name per line) to ATT&CK Enterprise techniques with an embedded keyword table of about 90 well-known techniques across all 14 tactics. Technique IDs already in the text (`T1003.001`) are recognised directly; IDs not in the table are listed as "verify on attack.mitre.org", never guessed. Lines starting with `#` are comments.

```bash
python3 scripts/attack_mapper.py examples/hunt_notes.txt
python3 scripts/attack_mapper.py notes.txt --json
python3 scripts/attack_mapper.py notes.txt --navigator layer.json --layer-name "IR-2026-114"
python3 scripts/attack_mapper.py --list          # the full embedded table
```

Text output: each technique with the keyword that matched and the line numbers, the lines that matched nothing, and a per-tactic coverage bar (matched / techniques in the table for that tactic). `--json` keys: `lines` (`line`, `text`, `techniques`), `techniques` (`id`, `name`, `tactics`, `matched`, `lines`), `coverage` (`tactic`, `tactic_id`, `shortname`, `matched`, `in_table`, `techniques`). `--navigator` writes a layer (format 4.5, domain `enterprise-attack`) where the score is the number of lines that hit the technique; load it at the ATT&CK Navigator with "Open Existing Layer". Exit `0` on success, `2` on bad input.

Keyword mapping is a starting point. Read every match: "lsass" in a line about an AV exclusion is not credential dumping.

## Output

Hand back a hunt record:

1. Hypothesis and time range
2. Indicators searched (defanged table: type, value, source line) and where (index, EDR, proxy)
3. ATT&CK techniques in scope, as a table:

| Technique | Name | Tactic | Data source | Result |
|---|---|---|---|---|

4. Findings: hits with host, user, process and timestamps, or "no hits"
5. Verdict: confirmed / refuted / inconclusive, and the logging gaps that limited the hunt
6. Follow-ups: detections to write, indicators to block, logs to turn on

## References

- `references/hunt-playbook.md` hypothesis template, the PEAK-style hunt loop, and per-technique data sources and hunt ideas for the techniques that come up most
- `references/ioc-handling.md` defang conventions, the pyramid of pain, IOC quality checks and sharing rules (TLP 2.0)
