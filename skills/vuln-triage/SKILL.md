---
name: vuln-triage
description: Prioritize vulnerabilities so the team fixes the right things first. Computes exact CVSS v3.1 base, temporal and environmental scores from a vector, audits Python and npm dependencies (requirements.txt, Pipfile.lock, poetry.lock, package.json, package-lock.json) against OSV.dev, flags loose pins, and ranks findings with known-exploited (CISA KEV) first plus a one-line-per-package upgrade plan. Use whenever someone pastes a CVSS vector or asks "how bad is this CVE", "what should we patch first", "are our dependencies vulnerable", "npm audit / pip-audit / Dependabot / Snyk says...", wants an SCA check in CI, or needs to triage a scanner or pentest report.
---

# Vuln Triage

Turn a pile of CVEs and scanner output into a short, defensible fix order.

## When to use

- A CVSS vector or score needs checking ("is this really 9.8?", "what is it for our environment?")
- "Are our dependencies vulnerable?", reviewing `requirements.txt`, lockfiles or `package.json`
- Dependabot, Snyk, `npm audit` or `pip-audit` produced too many alerts to read
- Building a patch plan or SLA report from a scan or pentest
- Adding a dependency gate to CI

## Ground rules

- Triage means ranking and fixing. No exploit code, no "proof" against systems you do not own. Use advisories, vendor notes and your own test environment
- `--online` sends package names and versions (nothing else) to api.osv.dev. Ask before using it on a private project whose dependency list is itself confidential; offline mode with `--osv-results` works without sending anything
- A CVSS base score describes the bug, not your risk. Say so in reports, and use environmental metrics or reachability to adjust, with the reason written down
- Never downgrade a known-exploited (KEV) item because its CVSS is moderate. Exploitation in the wild beats the score
- Version matching against saved OSV data is approximate (PEP 440 / semver ordering). Confirm borderline matches against the advisory

## Workflow

1. Collect inputs: manifests and lockfiles (lockfiles are better, they hold real versions), scanner output, CVE list
2. Run `dep_audit.py <project dir>` offline first for pinning problems, then with `--online` (or `--osv-results`) for known vulnerabilities. Add `--kev` with the CISA KEV catalog JSON when you have it
3. For any finding someone disputes, recompute its vector with `cvss_calc.py`, then add environmental metrics for your deployment (internal only = `MAV:A`, low-value data = `CR:L`)
4. Rank with `--prioritize`: P1 known exploited or critical, P2 high, P3 medium, P4 the rest. Within a bucket: KEV, then score, then production deps before dev deps
5. Check reachability for P1/P2: is the vulnerable function used, is the package only in dev or build tooling? Note the answer next to the finding
6. Hand back the upgrade plan (one line per package) and the target dates from `references/triage-playbook.md`

## Tools

### cvss_calc.py

Exact CVSS v3.1 calculator (FIRST spec formulas and Roundup). Base, temporal (E, RL, RC) and environmental (CR/IR/AR and modified metrics) scores.

```bash
python3 scripts/cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"          # 9.8 critical
python3 scripts/cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"          # 6.1 medium
python3 scripts/cvss_calc.py --file examples/vectors.txt --json
```

- Validates the vector: prefix, known metrics, allowed values, no duplicates, all 8 base metrics present. Bad vectors exit 2
- `score`/`severity` in the output are the most specific score present (environmental, else temporal, else base); `--fail-on` uses that
- CVSS:3.0 vectors are scored with 3.1 formulas and carry a note (rounding can differ by 0.1). CVSS v4.0 vectors are rejected, not guessed

### dep_audit.py

Dependency audit with a prioritized view.

```bash
python3 scripts/dep_audit.py examples/python-app examples/node-app                           # offline: pinning checks
python3 scripts/dep_audit.py examples/python-app examples/node-app \
    --osv-results examples/osv-results.json --kev examples/kev.json --prioritize             # offline match + ranking
python3 scripts/dep_audit.py . --online --prioritize                                         # live OSV.dev
python3 scripts/dep_audit.py package-lock.json --online --no-dev --json --fail-on critical   # CI gate
```

- Parses `requirements.txt` (extras, markers, hashes, `-e`, `name @ url`), `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json` v1/v2/v3. A directory means the known files inside it. The same package and version from several files is reported once
- DEP-001 known vulnerability: severity from the advisory's CVSS v3 vector (computed), else its label (GHSA `MODERATE` = medium), else medium. Extra keys: `package, version, ecosystem, vuln_id, aliases, cves, cvss, fixed, kev, dev, priority`. Advisories that alias each other (GHSA/PYSEC/CVE) are merged per package
- DEP-010 version range (low; info for `package.json` ranges when a `package-lock.json` sits next to it), DEP-011 installed from URL/git (low), DEP-012 no version or `*`/`latest` (medium)
- `--osv-results` accepts any JSON holding OSV vulnerability objects: `/v1/vulns/<id>` responses, a list, or `osv-scanner --format json` output
- `--kev` takes the CISA KEV catalog JSON (`vulnerabilities[].cveID`) or any text containing CVE ids. Advisories can also carry `kev: true`
- JSON: `mode, dependencies, findings, upgrades`. `upgrades` has one entry per vulnerable package: `package, version, target` (lowest version that clears every advisory with a fix), `fixes`, `unfixed`, `top` priority

Both tools: exit `1` when anything is at or above `--fail-on` (default `high`), `2` on bad input.

## Output

Lead with counts: dependencies checked, vulnerabilities by priority, how many are KEV. Then:

| Priority | Package | Version | Advisory (CVE) | Severity / CVSS | Fixed in | KEV | Reachable? |
|---|---|---|---|---|---|---|---|

Then the upgrade plan, one line per package, and the due dates from the playbook. State the data source and date (OSV online on 2026-05-01, or the saved file), and what was not covered (container images, OS packages, transitive deps without a lockfile).

## References

- `references/cvss-v31-cheatsheet.md` every metric, its values and weights, severity bands, scoring pitfalls
- `references/triage-playbook.md` priority buckets, SLA table, reachability questions, exception template, VEX status words
