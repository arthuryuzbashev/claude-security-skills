---
name: security-recon
description: Passive attack-surface review for domains you own or are authorized to assess. Grades email authentication (SPF, DMARC per RFC 9989 incl. np and t=y, DKIM, MTA-STS, TLS-RPT, BIMI) against current Gmail, Yahoo and Outlook sender rules, checks security.txt (RFC 9116), CAA and DNSSEC, and maps subdomains from CT logs, DNS exports or asset lists, flagging admin/dev/CI/API-docs hosts, public names pointing at private IPs and dangling CNAMEs that could allow subdomain takeover. Use whenever someone asks "can my domain be spoofed", "check my SPF/DMARC", "why does mail land in spam", BIMI or logo in Gmail, security.txt or CAA, "what subdomains do we expose", "audit our external footprint", pastes crt.sh output or a subdomain list, or is preparing the recon/scoping phase of an authorized pentest or bug bounty.
---

# Security Recon

Show what a domain exposes to the internet, from public data only, and turn it into a short list of fixes.

## When to use

- "Is our email spoofable?", SPF/DMARC/DKIM questions, DMARC rollout planning, MTA-STS setup
- A list of subdomains, a crt.sh export or a DNS zone dump needs sorting into "fine" and "look at this"
- Hunting stale DNS: old CNAMEs to Heroku, S3, Azure, GitHub Pages and similar
- The scoping and recon phase of an authorized pentest, red team or bug bounty
- A periodic external-footprint check for your own organisation
- security.txt, CAA or DNSSEC questions, or a BIMI logo that does not show
- For HTTP security headers, cookies and TLS use the `web-appsec` and `crypto-tls` skills; this one stays at DNS and public records

## Ground rules

- Only map domains the user owns or has written permission to assess. For a bug bounty, read the program's scope first: in-scope domains, excluded hosts, whether automated DNS lookups are allowed
- Stay passive. These tools read public DNS records and certificate logs. No port scans, no brute-force subdomain guessing, no login attempts, no vulnerability probes. Anything active needs an explicit go-ahead and a scope
- A dangling CNAME is a candidate, not a confirmed takeover. Never register the abandoned resource on someone else's domain to "prove" it. On your own domain, the fix is to delete the record or re-claim the resource
- Keep the evidence: the input file, the command and the date. DNS changes, so a finding without a timestamp is hard to defend later
- Treat host lists as sensitive. Internal names in a report help attackers as much as defenders

## Workflow

Copy this checklist and tick it off:

```
- [ ] 1. Scope and exclusions written down
- [ ] 2. email_auth_audit.py per domain
- [ ] 3. domain_posture.py per domain
- [ ] 4. Names collected (CT, zone export, inventory)
- [ ] 5. surface_map.py with DNS answers
- [ ] 6. High findings verified by hand
- [ ] 7. Report with sources, date and gaps
```

1. Confirm the domain list and scope. Write down excluded hosts before collecting anything
2. Email auth: run `email_auth_audit.py <domain>` (live, needs `dig`) or on saved records with `--file`. Fix order: DMARC missing or broken, SPF permerrors, then DMARC enforcement. Re-run after each DNS change until the grade stops moving
3. Run `domain_posture.py <domain>` for security.txt, CAA and DNSSEC
4. Collect names passively: crt.sh JSON (`https://crt.sh/?q=%25.<domain>&output=json`), the DNS zone export from the DNS provider, the cloud asset inventory. Save them to files
5. Run `surface_map.py <file> --domain <domain>` to de-dup and classify. Add `--records` with saved `dig` answers, or `--resolve` for live lookups, to catch private IPs and dangling CNAMEs
6. Verify every high finding by hand (`dig CNAME <host>`, open the provider's error page) before reporting it
7. Report with `references/recon-scope-checklist.md` in mind: what was in scope, which sources were used, what was not checked

## Tools

### email_auth_audit.py

Grades SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI. Score 0-100 with a letter grade.

```bash
python3 scripts/email_auth_audit.py example.com                        # live: dig TXT lookups, MTA-STS policy over HTTPS
python3 scripts/email_auth_audit.py example.com --selector google      # DKIM selectors to try (default: a common list)
python3 scripts/email_auth_audit.py --file examples/weak_records.txt   # saved dig/zone TXT lines
python3 scripts/email_auth_audit.py --spf "v=spf1 a mx ?all" --dmarc "v=DMARC1; p=none"
python3 scripts/email_auth_audit.py --file records.txt --mta-sts-policy mta-sts.txt --json
python3 scripts/email_auth_audit.py --bimi "v=BIMI1; l=https://example.com/logo.svg" --dmarc "v=DMARC1; p=reject"
```

- SPF: missing (EML-001), several records (EML-002), unknown mechanism (EML-003), `+all` (EML-004), `?all` (EML-005), `~all` note (EML-006), no `all` (EML-007), `ptr` (EML-008), more than 10 DNS lookups (EML-009), nested includes not counted offline (EML-010), include with no SPF record (EML-011), `ip4` wider than /16 or `ip6` wider than /32 (EML-012)
- DMARC (RFC 9989, May 2026): missing (DMR-001), several (DMR-002), bad version tag (DMR-003), bad or missing `p` (DMR-004, medium when a mailto `rua` makes it count as `p=none`), `p=none` (DMR-005), `sp=none` under enforcement (DMR-006), bad `pct` (DMR-007), `pct<100` (DMR-008, `pct` is removed in RFC 9989 and ignored by updated receivers), no `rua` (DMR-009), test mode `t=y` under enforcement (DMR-010), `np=none` (DMR-011), report URI that is not `mailto:` (DMR-012)
- DKIM: none found at the tried selectors (DKM-001), revoked (DKM-002), no key (DKM-003), unreadable key (DKM-004), RSA under 1024 (DKM-005) or under 2048 bits (DKM-006), test mode `t=y` (DKM-007)
- MTA-STS: missing (MTS-001), several (MTS-002), bad `id` (MTS-003), bad policy (MTS-004), testing (MTS-005), none (MTS-006), no mx (MTS-007), short `max_age` (MTS-008), `max_age` above 31557600 (MTS-009). TLS-RPT: missing (TRP-001), no `rua` (TRP-002)
- BIMI (only when a record exists): DMARC not strong enough (BIM-001), logo not an HTTPS SVG (BIM-002), no VMC/CMC `a=` (BIM-003, info), several records or no `l=` (BIM-004). Live mode looks up `default._bimi`
- The SPF lookup count follows `include` and `redirect` when it can: live via `dig`, offline when the include targets' TXT lines are in the same `--file`
- With record text flags (`--spf`, `--dmarc` ...) only the records you pass are checked. With `--file` or a domain, missing records are findings

### domain_posture.py

Checks security.txt, CAA and DNSSEC.

```bash
python3 scripts/domain_posture.py example.com                    # live: dig CAA/DS, one HTTPS GET for security.txt
python3 scripts/domain_posture.py example.com --no-fetch         # DNS only
python3 scripts/domain_posture.py www.example.test --records examples/posture_records.txt --security-txt examples/security.txt --today 2026-11-19
```

- security.txt (RFC 9116): missing (STX-001), no `Contact` (STX-002), no `Expires` (STX-003), expired (STX-004), `Expires` more than a year ahead (STX-005), `Contact` or link not a URI or over http:// (STX-006), `Expires` repeated or unparsable (STX-007), only at the legacy `/security.txt` (STX-008). PGP cleartext signatures are handled
- CAA (RFC 8659): none (CAA-001), critical flag on an unknown tag that blocks issuance (CAA-002), no `iodef` (CAA-003, info)
- DNSSEC: no DS record for the zone (DNS-001)
- CAA and DS are looked up from the closest ancestor that has them, so `www` inherits the zone's records. With saved files only the given inputs are checked; a `--records` file without CAA or DS lines counts as missing

### surface_map.py

De-dups and classifies hostnames, then (optionally) checks their DNS answers.

```bash
python3 scripts/surface_map.py examples/hosts.txt --domain example.test
python3 scripts/surface_map.py examples/crtsh.json --domain example.test --json
python3 scripts/surface_map.py examples/hosts.txt --records examples/dns_answers.txt   # offline DNS checks
python3 scripts/surface_map.py hosts.txt --domain example.com --resolve                 # live lookups
```

- Input: plain list, crt.sh JSON (`name_value`), or CSV (first column). URLs, ports, trailing dots and case are cleaned; `--domain` drops out-of-scope names
- Name categories (whole words in the subdomain, digits ignored, so `dev2` and `jenkins-old` match): ci-cd SRF-001, admin SRF-002, data SRF-003 (medium); monitoring SRF-004, non-prod SRF-005, legacy SRF-006, remote-access SRF-007, api-docs (swagger, openapi, graphql) SRF-011 (low); internal SRF-008, auth SRF-009, storage SRF-010 (info)
- DNS checks: private, loopback or link-local address in public DNS (SRF-020), CNAME to a takeover-prone service that does not resolve (SRF-021, high; the service list follows the public can-i-take-over-xyz status list, services marked not vulnerable such as WP Engine and Zendesk fall to SRF-022), any other CNAME that does not resolve (SRF-022), name with no address (SRF-023). Wildcards are SRF-030
- RFC 5737 documentation ranges are not counted as private

All tools: `--json` for machines, exit `1` when a finding is at or above `--fail-on` (default `high`), `2` on bad input. JSON keys: `email_auth_audit.py` gives `target, records, spf_lookups, score, grade, findings`; `domain_posture.py` gives `target, checks, security_txt, caa, dnssec, findings`; `surface_map.py` gives `summary, hosts, rejected, findings`.

## Output

Start with one line per domain: email grade, number of hosts, number of high findings. Then:

| Severity | ID | Host / record | Issue | Fix |
|---|---|---|---|---|

For email auth, give the exact record to publish (full TXT value), not just "tighten DMARC". For the surface map, group hosts by category and list only the ones that need a decision. Close with the sources used, the date, and what was not covered (no port scan, no app testing, DKIM selectors not found).

## References

- `references/email-auth-cheatsheet.md` record syntax incl. RFC 9989 DMARC tags, Gmail/Yahoo/Outlook sender rules, safe rollout order for DMARC and MTA-STS, BIMI, lookup-limit tricks. Open it before writing a record for the user
- `references/recon-scope-checklist.md` scoping questions, passive sources, security.txt/CAA/DNSSEC good states, how to verify a takeover candidate safely, report checklist
