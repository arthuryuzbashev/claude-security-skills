# Vulnerability triage playbook

The goal is a fix order you can defend: why this first, by when, and what was accepted instead of fixed.
Facts checked 2026-11-19: CISA BOD 26-04 (issued 2026-06-10), CISA KEV catalog 2026.11.18, SSVC CISA Coordinator v2.0.3, EPSS API.

## Contents

- Priority buckets
- SSVC and BOD 26-04 (`ssvc_decide.py`)
- KEV fields worth reading
- EPSS: how to use it and how not to
- Raise or lower a finding
- Reachability questions
- VEX status words
- Exception / risk acceptance template
- Daily SCA hygiene

## Priority buckets (what `dep_audit.py --prioritize` uses)

| Priority | Rule | Default target |
|---|---|---|
| P1 | In CISA KEV (known exploited) or CVSS 9.0+ | Internet-facing: 7 days or less. Internal: 14 days |
| P2 | High (7.0-8.9) | 30 days |
| P3 | Medium (4.0-6.9) | 90 days |
| P4 | Low, info, unrated with no exploit | Next routine upgrade |

These targets are a starting point. Your policy, contract or regulator may set others; use theirs and write the source in the report. For US federal civilian agencies BOD 26-04 now sets the timelines (it revoked BOD 22-01 and BOD 19-02); see the next section. Non-federal teams often adopt it as a defensible public baseline.

## SSVC and BOD 26-04 (`ssvc_decide.py`)

SSVC (Stakeholder-Specific Vulnerability Categorization, CERT/CC and CISA) replaces "sort by CVSS" with a decision tree. CISA publishes its Coordinator inputs for many CVEs in the CVE record (CISA ADP, "Vulnrichment").

| Input | Values | Where it comes from |
|---|---|---|
| Exploitation | none, poc (public proof of concept), active | KEV listing = active; CISA ADP; vendor and threat intel |
| Automatable | yes, no | Can an attacker run steps 1-4 of the kill chain (recon to exploitation) without a human? CISA ADP |
| Technical Impact | partial, total | Total = full control of the vulnerable component or all its data. CISA ADP |
| Mission and Well-Being | low, medium, high | Yours: how much the affected asset matters to your mission and to people |

CISA Coordinator v2.0.3 outcomes, in rising order: Track (normal cycle), Track* (normal cycle, watch closely), Attend (faster than normal, tell owners), Act (now, leadership involved). Act only happens with active exploitation; the full 36-row table is in the script.

BOD 26-04 timelines (federal civilian agencies; table v1.0.0):

| In KEV | Internet exposed | Automatable | Impact total | Impact partial |
|---|---|---|---|---|
| yes | yes | yes | 3 days + forensic triage | 3 days |
| yes | yes | no | 3 days + forensic triage | 14 days |
| yes | no | yes | 3 days + forensic triage | 14 days |
| yes | no | no | 14 days | 14 days |
| no | yes | yes | 3 days | 14 days |
| no | yes | no | 14 days | 60 days |
| no | no | yes | 60 days | 60 days |
| no | no | no | fix on system upgrade | fix on system upgrade |

When data is missing the directive treats a CVE as not automatable with total impact. `ssvc_decide.py` uses that default for non-KEV CVEs, the worst case (automatable, total) for KEV CVEs, and assumes exposed and high mission when you do not say otherwise. Every assumption is printed; replace it with a real answer before you publish the result.

## KEV fields worth reading

The catalog JSON (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) carries per entry:
- `dateAdded`, `dueDate`: the federal deadline; `dep_audit.py` copies it into `kev_due_date`
- `knownRansomwareCampaignUse`: `Known` or `Unknown`; Known goes to the top of P1 in practice (`kev_ransomware`)
- `forensicTriage`: `Yes` means BOD 26-04 asks for CISA's forensic triage steps on affected assets, not only a patch
- `requiredAction`, `notes`, `cwes`

## EPSS: how to use it and how not to

EPSS (FIRST) gives each CVE a daily probability of exploitation activity in the next 30 days plus a percentile. API: `https://api.first.org/data/v1/epss?cve=CVE-...`; daily bulk CSV linked from https://www.first.org/epss/data_stats. The first CSV line names the model (`#model_version:v2026.06.15` on 2026-11-19); v4 was released 2025-03-17. Scores shift when the model changes, so record the model version and date with any score you report.

- Use it to order work inside a bucket (`dep_audit.py --epss` does that) and to spot non-KEV items that deserve a closer look (high percentile)
- It is a probability across the whole internet, not a verdict for your asset. A low EPSS never cancels KEV or a vendor "exploited in the wild" note
- Do not feed EPSS into SSVC Exploitation. That input is evidence (none, poc, active), not likelihood

## Raise or lower a finding

Raise when:
- The vulnerable code is reachable from the internet without login
- A public exploit or active campaign exists (KEV, vendor says "exploited in the wild", SSVC Exploitation is poc or active, EPSS percentile is high)
- The asset holds credentials, payment data, personal data, or can deploy code (CI/CD)

Lower (write down why) when:
- The package is dev or build only and never ships (test runners, linters). Still fix at the next routine upgrade
- The vulnerable function is not called, confirmed by code search or a reachability tool
- The required configuration is not used (feature off, platform not affected)
- A compensating control removes the attack path, not just makes it harder

## Reachability questions

1. Is the package in the production artifact (image, bundle, wheel) or only in dev tooling?
2. Which function or feature does the advisory name? Search the code for it
3. Does user-controlled input reach that function?
4. Is the service exposed to the internet, a partner network, or only internal?
5. Is there a fixed version that does not break us? Check the changelog for majors

## VEX status words

When you publish or exchange triage results (CycloneDX VEX, CSAF VEX, OpenVEX), use these statuses:

- `not_affected` with a justification (component not present, vulnerable code not present, vulnerable code not in execute path, cannot be controlled by an adversary, inline mitigations exist)
- `affected` with the action statement (upgrade to X)
- `fixed` in which version
- `under_investigation` with a date for the answer

## Exception / risk acceptance template

```
Finding:        <package> <version> <advisory id / CVE>
Priority:       P2 (CVSS 7.5, not in KEV)
Why not fixed:  fixed version needs framework major upgrade, planned in Q3
Mitigation:     endpoint behind SSO, WAF rule <id>, input validated in <file>
Owner:          <name>
Expires:        <date, 90 days max>, then re-review
Approved by:    <name, role>
```

## Daily SCA hygiene

- Commit lockfiles. Scan the lockfile, not the manifest
- Fail CI on P1 only at first (`--fail-on critical` plus KEV review), then tighten
- One upgrade often fixes many advisories: work from the upgrade plan, not the advisory list
- Re-run with `--online` weekly; new advisories land on old versions
- Keep the KEV catalog fresh: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed linked there)
- Prefer the CVSS v4.0 vector when an advisory carries both. A v4 base score (CVSS-B) assumes active exploitation until you add `E`, so it is a worst case, not a measurement
