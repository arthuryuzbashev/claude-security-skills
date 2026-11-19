# Risk scoring and register guide

How to fill in the register that `risk_register.py` reads, so scores mean the same thing to everyone.

## Write the risk as a sentence

"<Threat or cause> leads to <event>, which causes <impact on the business>."
Good: "Phishing leads to email account takeover, which exposes customer contracts."
Not a risk: "Phishing" (a threat), "No MFA" (a weakness), "GDPR" (a requirement).

## Likelihood (1-5), over the next 12 months

| Score | Label | Rule of thumb |
|---|---|---|
| 1 | Rare | Not seen in the sector, needs several unlikely things at once |
| 2 | Unlikely | Could happen, no known attempts against us |
| 3 | Possible | Happens to peers; we have seen attempts |
| 4 | Likely | Expected within the year; seen it here before |
| 5 | Almost certain | Happening now or several times a year |

## Impact (1-5), worst credible case

| Score | Label | Money | Operations | Data / people | Reputation / legal |
|---|---|---|---|---|---|
| 1 | Negligible | < 0.1% revenue | Minutes of disruption | No sensitive data | None |
| 2 | Minor | 0.1-1% | Hours, one team | Internal data, few records | Local complaints |
| 3 | Moderate | 1-3% | A day, one service | Confidential data, limited | Customer notices, regulator query |
| 4 | Major | 3-10% | Days, several services | Large personal data breach | National press, fines |
| 5 | Severe | > 10% | Weeks, core business stops | Special-category data, safety | Licence loss, executive exit |

Tune the money bands to the organization. Score impact on the worst credible case, not the worst imaginable one.

## Scores and bands (the script's defaults)

Inherent = likelihood x impact (1-25). Bands: 1-4 low, 5-9 medium, 10-14 high, 15-25 critical.
Change `BANDS` at the top of `risk_register.py` if your policy uses different cut-offs.

Residual risk, in order of preference:
1. Explicit `residual_likelihood` and `residual_impact` (best: forces a real re-assessment)
2. `control_effectiveness`: residual = inherent x (1 - effectiveness), floored at 1
   - none 0%, weak/low 25%, partial/medium 50%, strong/high 75%, or a number (0.6, 60%)
   - "strong" needs evidence the control works (a test, an audit, metrics), not just that it exists

Most controls lower likelihood (MFA, patching). Some lower impact (backups, encryption, segmentation).
When you give explicit residual values, move the right axis.

## Treatment options

| Treatment | Means | Needs |
|---|---|---|
| Mitigate | Add or improve controls | Actions, owners, dates |
| Transfer | Insurance or contract moves the cost | Policy or clause reference; the reputational risk stays |
| Avoid | Stop the activity | Decision record |
| Accept | Live with it | Named approver at the right level, expiry date, review |

Accepting high or critical residual risk should need senior sign-off (the script flags it as RR-004).

## Review cadence

| Residual rating | Review at least |
|---|---|
| Critical | Monthly, until treated |
| High | Quarterly |
| Medium | Every 6 months |
| Low | Yearly |

Also review after an incident, a major change, a new supplier for a critical service, or an audit finding.

## Register columns

Required: `id`, `title`, `likelihood`, `impact`.
Recommended: `owner`, `category`, `control_effectiveness`, `controls`, `treatment`, `last_review`, `next_review`, `status`.
Optional: `residual_likelihood`, `residual_impact`. Dates are ISO (`2026-11-19`). `status: closed` keeps a row for history but leaves it out of the analysis.

## Script finding ids

| ID | Meaning |
|---|---|
| RR-001 | Open risk with no owner |
| RR-002 | Review date passed |
| RR-003 | No review date at all |
| RR-004 | High or critical residual risk accepted |
| RR-005 | High or critical residual risk with no treatment decision |
| RR-006 | Residual score above inherent |
| RR-007 | Control effectiveness claimed with no controls listed |
