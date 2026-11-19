# CVSS v4.0 cheat sheet

Source: FIRST CVSS v4.0 Specification Document (https://www.first.org/cvss/v4.0/specification-document, v1.2) and the FIRST reference calculator. `cvss_calc.py` uses the same MacroVector table and steps as that calculator (checked against it on 6000 random vectors, 0 differences).

## Contents

- What changed from v3.1
- Base metrics
- Threat and environmental metrics
- Supplemental metrics
- How the score is computed
- Nomenclature and reporting
- Pitfalls

## What changed from v3.1

- No formula with weights. Each vector maps to one of 270 "MacroVectors" (6 equivalence classes) with a score set by experts, then the score moves within that class by how far the vector sits from the class's worst case
- Scope is gone. Impact is split into the Vulnerable system (VC/VI/VA) and Subsequent systems (SC/SI/SA)
- New Attack Requirements (AT): conditions in the target that the attacker does not control (a race, a specific config), separate from Attack Complexity (AC: defeating defenses such as ASLR)
- User Interaction has three values: None, Passive (victim does something normal, like opening a page), Active (victim has to do something unusual)
- Temporal is renamed Threat and keeps only Exploit Maturity (E). Remediation Level and Report Confidence are gone
- Not set (`X`) for E means Attacked: a vector without threat data scores as worst case

## Base metrics

| Metric | Values | Ask yourself |
|---|---|---|
| AV Attack Vector | N, A, L, P | From where can the attacker reach the vulnerable system? |
| AC Attack Complexity | L, H | Must the attacker defeat a security control (ASLR, DEP, a secret)? |
| AT Attack Requirements | N, P | Must something outside the attacker's control be in place (race, config, MITM position)? |
| PR Privileges Required | N, L, H | What account does the attacker need? |
| UI User Interaction | N, P, A | None, Passive, Active involvement of a person other than the attacker |
| VC / VI / VA | H, L, N | Impact on the vulnerable system |
| SC / SI / SA | H, L, N | Impact on systems after it (browser of a user hit by XSS, hosts behind a gateway) |

## Threat and environmental metrics

- E Exploit Maturity: A Attacked (default when X), P POC public, U Unreported
- CR / IR / AR security requirements: H (default when X), M, L
- Modified base metrics MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA override base values for your environment. MSI and MSA add S (Safety): subsequent impact can hurt people

## Supplemental metrics

S Safety, AU Automatable, R Recovery, V Value Density, RE Vulnerability Response Effort, U Provider Urgency (Clear, Green, Amber, Red). They do not change the score; `cvss_calc.py` validates them and lists them under `supplemental`. AU here is the same idea as SSVC Automatable.

## How the score is computed

1. Fill defaults (E:X = A, CR/IR/AR:X = H, modified metrics override base)
2. If all six impact metrics are N, the score is 0.0
3. Compute the six equivalence classes (EQ1 AV/PR/UI, EQ2 AC/AT, EQ3 VC/VI/VA, EQ4 SC/SI/SA plus Safety, EQ5 E, EQ6 CR/IR/AR with VC/VI/VA). The six digits are the MacroVector
4. Look up the MacroVector score, then subtract the mean distance to the next lower MacroVector in each class, scaled by how far the vector is from that class's highest-severity vector
5. Clamp to 0-10 and round to one decimal

Severity bands are the same as v3.1: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.

## Nomenclature and reporting

| Label | Metrics used |
|---|---|
| CVSS-B | Base only |
| CVSS-BT | Base and Threat |
| CVSS-BE | Base and Environmental |
| CVSS-BTE | All three |

Always write the label next to the number ("CVSS-BT 8.1"). A v4 number without its label is ambiguous, and a v4 score is not comparable 1:1 with a v3.1 score of the same bug.

## Pitfalls

- A vendor's CVSS-B is a worst case because E defaults to Attacked. Add `E:U` or `E:P` from threat data (KEV, EPSS, vendor notes) before ranking; `E:U` on a 9.3 RCE gives 8.1
- Do not translate v3.1 vectors to v4 by hand. Score each version from its own vector and keep both if the advisory has both
- Metric order in the vector string is fixed by the spec; `cvss_calc.py` accepts any order, other tools may not
