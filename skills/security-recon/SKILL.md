---
name: security-recon
description: Passive attack-surface review for domains you own or are authorized to assess. Grades email authentication (SPF, DMARC, DKIM, MTA-STS, TLS-RPT) and maps subdomains from CT logs, DNS exports or asset lists, flagging admin/dev/staging/CI hosts, public names pointing at private IPs and dangling CNAMEs that could allow subdomain takeover. Use whenever someone asks "can my domain be spoofed", "check my SPF/DMARC", "why does mail land in spam", "what subdomains do we expose", "audit our external footprint", pastes crt.sh output or a subdomain list, or is preparing the recon/scoping phase of an authorized pentest or bug bounty.
---

# Security Recon

Show what a domain exposes to the internet, from public data only, and turn it into a short list of fixes.

## When to use

- "Is our email spoofable?", SPF/DMARC/DKIM questions, DMARC rollout planning, MTA-STS setup
- A list of subdomains, a crt.sh export or a DNS zone dump needs sorting into "fine" and "look at this"
- Hunting stale DNS: old CNAMEs to Heroku, S3, Azure, GitHub Pages and similar
- The scoping and recon phase of an authorized pentest, red team or bug bounty
- A periodic external-footprint check for your own organisation

## Ground rules

- Only map domains the user owns or has written permission to assess. For a bug bounty, read the program's scope first: in-scope domains, excluded hosts, whether automated DNS lookups are allowed
- Stay passive. These tools read public DNS records and certificate logs. No port scans, no brute-force subdomain guessing, no login attempts, no vulnerability probes. Anything active needs an explicit go-ahead and a scope
- A dangling CNAME is a candidate, not a confirmed takeover. Never register the abandoned resource on someone else's domain to "prove" it. On your own domain, the fix is to delete the record or re-claim the resource
- Keep the evidence: the input file, the command and the date. DNS changes, so a finding without a timestamp is hard to defend later
- Treat host lists as sensitive. Internal names in a report help attackers as much as defenders

## Workflow

1. Confirm the domain list and scope. Write down excluded hosts before collecting anything
2. Email auth: run `email_auth_audit.py <domain>` (live, needs `dig`) or on saved records with `--file`. Fix order: DMARC missing or broken, SPF permerrors, then DMARC enforcement
3. Collect names passively: crt.sh JSON (`https://crt.sh/?q=%25.<domain>&output=json`), the DNS zone export from the DNS provider, the cloud asset inventory. Save them to files
4. Run `surface_map.py <file> --domain <domain>` to de-dup and classify. Add `--records` with saved `dig` answers, or `--resolve` for live lookups, to catch private IPs and dangling CNAMEs
5. Verify every high finding by hand (`dig CNAME <host>`, open the provider's error page) before reporting it
6. Report with `references/recon-scope-checklist.md` in mind: what was in scope, which sources were used, what was not checked

## Tools

### email_auth_audit.py

Grades SPF, DMARC, DKIM, MTA-STS and TLS-RPT. Score 0-100 with a letter grade.

```bash
python3 scripts/email_auth_audit.py example.com                        # live: dig TXT lookups, MTA-STS policy over HTTPS
python3 scripts/email_auth_audit.py example.com --selector google      # DKIM selectors to try (default: a common list)
python3 scripts/email_auth_audit.py --file examples/weak_records.txt   # saved dig/zone TXT lines
python3 scripts/email_auth_audit.py --spf "v=spf1 a mx ?all" --dmarc "v=DMARC1; p=none"
python3 scripts/email_auth_audit.py --file records.txt --mta-sts-policy mta-sts.txt --json
```

- SPF: missing (EML-001), several records (EML-002), unknown mechanism (EML-003), `+all` (EML-004), `?all` (EML-005), `~all` note (EML-006), no `all` (EML-007), `ptr` (EML-008), more than 10 DNS lookups (EML-009), nested includes not counted offline (EML-010), include with no SPF record (EML-011)
- DMARC: missing (DMR-001), several (DMR-002), bad version tag (DMR-003), bad or missing `p` (DMR-004), `p=none` (DMR-005), `sp=none` under enforcement (DMR-006), bad `pct` (DMR-007), `pct<100` (DMR-008), no `rua` (DMR-009)
- DKIM: none found at the tried selectors (DKM-001), revoked (DKM-002), no key (DKM-003), unreadable key (DKM-004), RSA under 1024 (DKM-005) or under 2048 bits (DKM-006), test mode `t=y` (DKM-007)
- MTA-STS: missing (MTS-001), several (MTS-002), bad `id` (MTS-003), bad policy (MTS-004), testing (MTS-005), none (MTS-006), no mx (MTS-007), short `max_age` (MTS-008). TLS-RPT: missing (TRP-001), no `rua` (TRP-002)
- The SPF lookup count follows `include` and `redirect` when it can: live via `dig`, offline when the include targets' TXT lines are in the same `--file`
- With record text flags (`--spf`, `--dmarc` ...) only the records you pass are checked. With `--file` or a domain, missing records are findings

### surface_map.py

De-dups and classifies hostnames, then (optionally) checks their DNS answers.

```bash
python3 scripts/surface_map.py examples/hosts.txt --domain example.test
python3 scripts/surface_map.py examples/crtsh.json --domain example.test --json
python3 scripts/surface_map.py examples/hosts.txt --records examples/dns_answers.txt   # offline DNS checks
python3 scripts/surface_map.py hosts.txt --domain example.com --resolve                 # live lookups
```

- Input: plain list, crt.sh JSON (`name_value`), or CSV (first column). URLs, ports, trailing dots and case are cleaned; `--domain` drops out-of-scope names
- Name categories (whole words in the subdomain, digits ignored, so `dev2` and `jenkins-old` match): ci-cd SRF-001, admin SRF-002, data SRF-003 (medium); monitoring SRF-004, non-prod SRF-005, legacy SRF-006, remote-access SRF-007 (low); internal SRF-008, auth SRF-009, storage SRF-010 (info)
- DNS checks: private, loopback or link-local address in public DNS (SRF-020), CNAME to a takeover-prone service that does not resolve (SRF-021, high), any other CNAME that does not resolve (SRF-022), name with no address (SRF-023). Wildcards are SRF-030
- RFC 5737 documentation ranges are not counted as private

Both tools: `--json` for machines, exit `1` when a finding is at or above `--fail-on` (default `high`), `2` on bad input. JSON keys: `email_auth_audit.py` gives `target, records, spf_lookups, score, grade, findings`; `surface_map.py` gives `summary, hosts, rejected, findings`.

## Output

Start with one line per domain: email grade, number of hosts, number of high findings. Then:

| Severity | ID | Host / record | Issue | Fix |
|---|---|---|---|---|

For email auth, give the exact record to publish (full TXT value), not just "tighten DMARC". For the surface map, group hosts by category and list only the ones that need a decision. Close with the sources used, the date, and what was not covered (no port scan, no app testing, DKIM selectors not found).

## References

- `references/email-auth-cheatsheet.md` record syntax, safe rollout order for DMARC and MTA-STS, lookup-limit tricks
- `references/recon-scope-checklist.md` scoping questions, passive sources, how to verify a takeover candidate safely, report checklist
