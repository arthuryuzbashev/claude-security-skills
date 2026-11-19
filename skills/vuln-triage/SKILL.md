---
name: vuln-triage
description: Prioritize vulnerabilities so the team fixes the right things first. Computes exact CVSS v3.1 (base, temporal, environmental) and CVSS v4.0 (CVSS-B/BT/BE/BTE) scores from a vector, makes SSVC decisions (CISA Coordinator v2.0.3) and CISA BOD 26-04 remediation timelines from CVE records with CISA Vulnrichment data, audits Python and npm dependencies (requirements.txt, Pipfile.lock, poetry.lock, package.json, package-lock.json) against OSV.dev, and ranks findings with known-exploited (CISA KEV) first, EPSS as tie-breaker and a one-line-per-package upgrade plan. Use whenever someone pastes a CVSS 3.1 or 4.0 vector or asks "how bad is this CVE", "what should we patch first", "what is the deadline for this KEV", "are our dependencies vulnerable", mentions SSVC, EPSS, KEV or BOD 26-04, "npm audit / pip-audit / Dependabot / Snyk says...", wants an SCA check in CI, or needs to triage a scanner or pentest report.
---

# Vuln Triage

Turn a pile of CVEs and scanner output into a short, defensible fix order.

## When to use

- A CVSS vector or score needs checking ("is this really 9.8?", "what is it for our environment?", a CVSS 4.0 vector from a new advisory)
- "Act now or next sprint?" for a CVE: SSVC decision and BOD 26-04 deadline
- "Are our dependencies vulnerable?", reviewing `requirements.txt`, lockfiles or `package.json`
- Dependabot, Snyk, `npm audit` or `pip-audit` produced too many alerts to read
- Building a patch plan or SLA report from a scan or pentest
- Adding a dependency gate to CI

## Ground rules

- Triage means ranking and fixing. No exploit code, no "proof" against systems you do not own. Use advisories, vendor notes and your own test environment
- `dep_audit.py --online` sends package names and versions (nothing else) to api.osv.dev; `ssvc_decide.py --online` fetches public CVE records from GitHub (cisagov/vulnrichment). Ask before using it on a private project whose dependency list is itself confidential; offline mode with `--osv-results` works without sending anything
- A CVSS base score describes the bug, not your risk. Say so in reports, and use environmental metrics or reachability to adjust, with the reason written down
- Never downgrade a known-exploited (KEV) item because its CVSS is moderate or its EPSS is low. Exploitation in the wild beats the score
- Say which inputs were assumed. `ssvc_decide.py` prints every assumption (exposure, mission, missing ADP data); ask the user for the real values before calling a decision final
- Version matching against saved OSV data is approximate (PEP 440 / semver ordering). Confirm borderline matches against the advisory

## Workflow

Copy this checklist and tick it off:

```
- [ ] 1. Inputs collected (lockfiles, scanner output, CVE list, KEV and EPSS files)
- [ ] 2. dep_audit.py offline, then with OSV data, --kev and --epss
- [ ] 3. Disputed scores recomputed with cvss_calc.py (v3.1 or v4.0)
- [ ] 4. ssvc_decide.py for P1/P2 CVEs, assumptions replaced with real answers
- [ ] 5. Reachability noted for P1/P2
- [ ] 6. Upgrade plan and due dates handed back with data sources and dates
```

1. Collect inputs: manifests and lockfiles (lockfiles are better, they hold real versions), scanner output, CVE list
2. Run `dep_audit.py <project dir>` offline first for pinning problems, then with `--online` (or `--osv-results`) for known vulnerabilities. Add `--kev` with the CISA KEV catalog JSON and `--epss` with the EPSS CSV when you have them
3. For any finding someone disputes, recompute its vector with `cvss_calc.py`, then add environmental metrics for your deployment (internal only = `MAV:A`, low-value data = `CR:L`). For v4.0 also add `E` from threat data; without it the score assumes active attack
4. Rank with `--prioritize`: P1 known exploited or critical, P2 high, P3 medium, P4 the rest. Within a bucket: KEV, then score, then production deps before dev deps
5. For P1/P2 CVEs run `ssvc_decide.py` with `--exposed` and `--mission` for the affected asset. Its decision and BOD 26-04 timeline set the due date; KEV entries with `forensicTriage: Yes` need more than a patch
6. Check reachability for P1/P2: is the vulnerable function used, is the package only in dev or build tooling? Note the answer next to the finding
7. Hand back the upgrade plan (one line per package) and the target dates from `references/triage-playbook.md`

## Tools

### cvss_calc.py

Exact CVSS calculator. v3.1: FIRST formulas and Roundup, base, temporal (E, RL, RC) and environmental scores. v4.0: the FIRST MacroVector table and interpolation (matches the reference calculator), with threat, environmental and supplemental metrics.

```bash
python3 scripts/cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"          # 9.8 critical
python3 scripts/cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"          # 6.1 medium
python3 scripts/cvss_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"    # 9.3 CVSS-B
python3 scripts/cvss_calc.py --file examples/vectors.txt --json
python3 scripts/cvss_calc.py --file examples/vectors-v4.txt
```

- Validates the vector: prefix, known metrics, allowed values, no duplicates, all 8 base metrics present. Bad vectors exit 2
- `score`/`severity` in the output are the most specific score present (environmental, else temporal, else base); `--fail-on` uses that
- CVSS:3.0 vectors are scored with 3.1 formulas and carry a note (rounding can differ by 0.1)
- v4.0 results: `score`, `severity`, `nomenclature` (CVSS-B, BT, BE, BTE), `macrovector`, `base_score` (base metrics only), `metrics`, `supplemental` when set, and a `note` when `E` is missing

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
- DEP-001 known vulnerability: severity from the advisory's CVSS v3 or v4 vector (computed, the higher wins), else its label (GHSA `MODERATE` = medium), else medium. Extra keys: `package, version, ecosystem, vuln_id, aliases, cves, cvss, fixed, kev, dev, priority`. Advisories that alias each other (GHSA/PYSEC/CVE) are merged per package
- DEP-010 version range (low; info for `package.json` ranges when a `package-lock.json` sits next to it), DEP-011 installed from URL/git (low), DEP-012 no version or `*`/`latest` (medium)
- `--osv-results` accepts any JSON holding OSV vulnerability objects: `/v1/vulns/<id>` responses, a list, or `osv-scanner --format json` output
- `--kev` takes the CISA KEV catalog JSON (`vulnerabilities[].cveID`) or any text containing CVE ids. Advisories can also carry `kev: true`. From the catalog, KEV findings get `kev_due_date` and `kev_ransomware`
- `--epss` takes the daily EPSS CSV or a saved api.first.org JSON. Findings get `epss` and `epss_percentile`, and EPSS orders findings inside a priority bucket (it never moves a finding to another bucket)
- JSON: `mode, dependencies, findings, upgrades`. `upgrades` has one entry per vulnerable package: `package, version, target` (lowest version that clears every advisory with a fix), `fixes`, `unfixed`, `top` priority

### ssvc_decide.py

SSVC decision (CISA Coordinator v2.0.3: Track, Track*, Attend, Act) and BOD 26-04 timeline (3 days with or without forensic triage, 14 days, 60 days, on upgrade) per CVE.

```bash
python3 scripts/ssvc_decide.py examples/vulnrichment-CVE-2099-0001.json --mission high --exposed yes
python3 scripts/ssvc_decide.py CVE-2099-1002 --kev examples/kev.json --epss examples/epss.csv --exposed no --mission medium --json
python3 scripts/ssvc_decide.py CVE-2021-44228 --online --exposed yes --mission high        # public Vulnrichment record
```

- Inputs: CVE ids with `--exploitation`/`--automatable`/`--impact` flags, CVE JSON 5 files or folders with the CISA ADP SSVC block, `--kev`, `--epss`. Flags override record values; a KEV listing forces Exploitation to active
- SSVC-001 per CVE. Severity is the higher of the decision (act critical, attend high, track* medium, track low) and the timeline (3 days critical, 14 days high, 60 days medium, upgrade low)
- JSON: `results` (`cve, decision, bod_26_04, inputs, assumed, kev_details, epss`), `findings`, `count`, `epss_model` when the CSV names it

All three tools: exit `1` when anything is at or above `--fail-on` (default `high`), `2` on bad input.

## Output

Lead with counts: dependencies checked, vulnerabilities by priority, how many are KEV. Then:

| Priority | Package | Version | Advisory (CVE) | Severity / CVSS | Fixed in | KEV / EPSS | SSVC / due | Reachable? |
|---|---|---|---|---|---|---|---|---|

Write CVSS v4 numbers with their label (CVSS-B 9.3), and list the SSVC assumptions that are still open.

Then the upgrade plan, one line per package, and the due dates from the playbook. State the data source and date (OSV online on 2026-05-01, KEV catalog version, EPSS model and score date, or the saved file), and what was not covered (container images, OS packages, transitive deps without a lockfile).

## References

- `references/cvss-v31-cheatsheet.md` every v3.1 metric, its values and weights, severity bands, scoring pitfalls
- `references/cvss-v40-cheatsheet.md` what changed in v4.0, metrics, how MacroVector scoring works, CVSS-B/BT/BE/BTE labels, pitfalls
- `references/triage-playbook.md` priority buckets, SSVC inputs and BOD 26-04 table, KEV fields, EPSS do and don't, reachability questions, exception template, VEX status words
