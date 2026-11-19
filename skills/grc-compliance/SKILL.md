---
name: grc-compliance
description: Governance, risk and compliance work for security teams. Scores and audits a CSV risk register (likelihood x impact, inherent vs residual risk, heat map, overdue reviews and treatment dates, expired risk acceptances, duplicate ids, missing owners) and runs a control gap assessment that maps 40 common security controls (MFA, asset inventory, logging, backups, encryption, vulnerability management, incident response and notification, vulnerability disclosure, software supply chain, vendor risk...) to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria and EU NIS2 Art. 20, 21(2) and 23, with coverage % and a prioritized gap list. Use when someone mentions a risk register, risk assessment, heat map, ISO 27001, SOC 2, NIST CSF, NIS2, DORA, the Cyber Resilience Act, gap analysis, readiness assessment, audit prep, Statement of Applicability, a security questionnaire or "are we compliant".
---

# GRC compliance

Turn a messy risk register or a pile of "do we have X?" answers into scored risks, framework coverage and a gap list someone can work through.

## When to use

- Reviewing or cleaning up a risk register before a management review or audit
- "Make me a heat map", "what are our top risks", "which reviews are overdue"
- SOC 2 or ISO 27001 readiness, a NIST CSF profile, a customer security questionnaire
- "How far are we from ISO 27001 / SOC 2?" or "what should we fix first?"
- Writing risk acceptance, treatment plans or a gap remediation roadmap

## Ground rules

- The control mappings are a starting point, not audit advice. Every output says so; keep that line in anything you hand over
- Never invent framework IDs. If a mapping is not in the script or the references and you are not sure of it, say "check the standard" instead of guessing a number
- A "yes" without evidence is a "partial". Ask what the evidence is (export, screenshot, ticket, report)
- Risk scores are judgments. Write down the reasoning for any score of 4 or 5 so the next reviewer can challenge it
- Registers often hold sensitive detail (unpatched systems, named people). Summarize, do not paste whole registers into external tools

## Workflow

### Risk register review

Copy this checklist and tick it off:

```
- [ ] Register exported to CSV, columns checked
- [ ] risk_register.py run with --today, exit 2 errors fixed
- [ ] Owners, overdue reviews, expired acceptances, overdue treatments read
- [ ] Top risks sanity checked against what leadership worries about
- [ ] Top risks, overdue list and actions per owner handed back
```

1. Get the register as CSV (export from the spreadsheet). Columns are described in `references/risk-scoring-guide.md`
2. Run `risk_register.py` with `--today` set to the review date
3. Fix data errors first (exit 2 lists every bad row), then read the findings: owners, overdue reviews, accepted high risks
4. Check the top risks make sense: does the heat map match what leadership worries about? If not, the scoring scales need agreeing
5. Hand back the top risks, the overdue list and the actions per owner

### Control gap assessment

```
- [ ] Scope agreed (entity, systems, frameworks; NIS2 only if the entity is in scope)
- [ ] Template answered with control owners, evidence asked for every "yes"
- [ ] control_gap.py run, critical "yes" answers challenged
- [ ] 30/90/180-day roadmap with owners, big gaps added to the register
```

1. `control_gap.py --template > answers.txt` and answer each control with the people who run it (yes / partial / no / na plus a note)
2. Run `control_gap.py answers.txt`
3. Challenge the "yes" answers on the critical controls (MFA, backups, vulnerability management) for evidence
4. Turn the top gaps into a roadmap: 30 / 90 / 180 days, owner per item; add the big ones to the risk register
5. Re-run after fixes to show coverage moving

## Tools

### risk_register.py

Scores a CSV risk register on 1-5 likelihood and impact. Inherent = L x I. Residual from explicit `residual_likelihood`/`residual_impact`, or inherent x (1 - control effectiveness) floored at 1. Bands: 1-4 low, 5-9 medium, 10-14 high, 15-25 critical.

```bash
python3 scripts/risk_register.py examples/risk_register.csv --today 2026-11-19
python3 scripts/risk_register.py register.csv --top 10 --review-days 90
python3 scripts/risk_register.py register.csv --json --fail-on medium
```

Output: counts by rating (inherent vs residual), inherent and residual 5x5 text heat maps, top risks by residual, overdue reviews, risks with no owner, findings.
Findings: RR-001 no owner, RR-002 review overdue (high when residual is critical), RR-003 no review date, RR-004 high/critical risk accepted, RR-005 high/critical with no treatment, RR-006 residual above inherent, RR-007 effectiveness claimed with no controls listed, RR-008 risk acceptance expired (`accepted_until` passed), RR-009 duplicate risk id, RR-010 treatment overdue (`treatment_due` passed on a risk that is not accepted). Closed rows are kept but not analysed (RR-009 still counts them).
Optional date columns: `accepted_until` (aliases `acceptance_expiry`, `accept_until`) and `treatment_due` (aliases `target_date`, `due_date`). A bad date there is a row error (exit 2).
`--review-days` sets the cycle used when only `last_review` is given (default 180).

JSON: `{summary: {today, total, open, inherent_by_rating, residual_by_rating, top_risks, overdue, missing_owner}, risks: [...], findings: [...]}`.

### control_gap.py

Maps answers on 40 common controls to NIST CSF 2.0 categories, ISO/IEC 27001:2022 Annex A controls, SOC 2 criteria and EU NIS2 articles (Art. 20 governance, Art. 21(2)(a)-(j) risk measures, Art. 23 reporting). NIS2 refs follow the Directive; Implementing Regulation (EU) 2024/2690 gives the detail for digital infrastructure and ICT providers. Coverage per framework item = average of its controls (yes 1, partial 0.5, no 0, na left out), framework coverage = average over the items this list maps.

```bash
python3 scripts/control_gap.py --template > answers.txt
python3 scripts/control_gap.py --list                                   # mapping table
python3 scripts/control_gap.py examples/control_answers.txt
python3 scripts/control_gap.py examples/control_answers.json --skip-unanswered --json
```

Answers: text lines `mfa: partial  admins only`, CSV `control,answer,note`, or JSON `{"mfa": "yes"}` / `{"mfa": {"answer": "yes", "note": "..."}}`. Keys or codes (`CTL-01`) both work.
Unanswered controls count as gaps ("not assessed") unless `--skip-unanswered`.
Gap severity: the control's priority when the answer is no, one step lower when partial. Gap ids `GAP-001`.. follow the control codes `CTL-01`..

JSON: `{disclaimer, controls, answers: {yes, partial, no, na, unanswered}, coverage: {csf: {framework, items_mapped, items_assessed, coverage_pct, full, partial, none, by_function}, iso: {...}, soc2: {...}, nis2: {...}}, findings: [{id, severity, title, detail, fix, location, control, status, answered, mappings}], warnings}`.

Both tools: exit `0` nothing at or above `--fail-on` (default `high`), `1` findings at or above it, `2` bad input.

## Output

Risk register review:

- One line: open risks, how many high/critical residual, how many overdue
- Top 5 risks table (ID, risk, owner, inherent, residual, treatment)
- Actions per owner, most urgent first
- The heat maps if the user wants something for a slide

Gap assessment:

| Framework | Coverage | Items fully covered |
|---|---|---|

Then the gap list (severity, control, framework refs, fix), a 30/90/180-day roadmap, and the disclaimer line.

## References

- `references/risk-scoring-guide.md` likelihood and impact scales, bands, residual rules, treatment options, review cadence, register columns and the RR finding ids. Open it before scoring or when someone disputes a score
- `references/framework-quick-reference.md` NIST CSF 2.0 functions and categories, ISO 27001:2022 clauses and Annex A themes, SOC 2 categories and the criteria the script uses, EU NIS2 / DORA / CRA scope and dates, plus a gap assessment playbook. Open it before explaining a mapping or an EU deadline
