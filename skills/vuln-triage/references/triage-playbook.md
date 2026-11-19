# Vulnerability triage playbook

The goal is a fix order you can defend: why this first, by when, and what was accepted instead of fixed.

## Priority buckets (what `dep_audit.py --prioritize` uses)

| Priority | Rule | Default target |
|---|---|---|
| P1 | In CISA KEV (known exploited) or CVSS 9.0+ | Internet-facing: 7 days or less. Internal: 14 days |
| P2 | High (7.0-8.9) | 30 days |
| P3 | Medium (4.0-6.9) | 90 days |
| P4 | Low, info, unrated with no exploit | Next routine upgrade |

These targets are a starting point. Your policy, contract or regulator may set others; use theirs and write the source in the report. For US federal civilian agencies, KEV entries carry a due date set by CISA under BOD 22-01.

## Raise or lower a finding

Raise when:
- The vulnerable code is reachable from the internet without login
- A public exploit or active campaign exists (KEV, vendor says "exploited in the wild", EPSS probability is high)
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
