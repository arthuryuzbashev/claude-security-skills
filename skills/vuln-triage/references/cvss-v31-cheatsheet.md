# CVSS v3.1 cheat sheet

Source: FIRST CVSS v3.1 Specification. `cvss_calc.py` implements these formulas exactly.

## Base metrics

| Metric | Values (weight) | Ask yourself |
|---|---|---|
| AV Attack Vector | N Network (0.85), A Adjacent (0.62), L Local (0.55), P Physical (0.2) | From where can the attacker reach the vulnerable component? |
| AC Attack Complexity | L Low (0.77), H High (0.44) | Do conditions outside the attacker's control have to line up (race, MITM position, specific config)? |
| PR Privileges Required | N (0.85), L (0.62, or 0.68 if S:C), H (0.27, or 0.5 if S:C) | What account does the attacker need before attacking? |
| UI User Interaction | N None (0.85), R Required (0.62) | Does a victim have to click, open or visit something? |
| S Scope | U Unchanged, C Changed | Does the impact reach a component with a different security authority (browser from a web app, host from a VM)? |
| C / I / A | H High (0.56), L Low (0.22), N None (0) | Impact on the impacted component: total loss, partial, none |

## Formulas

```
ISS            = 1 - (1 - C) * (1 - I) * (1 - A)
Impact (S:U)   = 6.42 * ISS
Impact (S:C)   = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
Exploitability = 8.22 * AV * AC * PR * UI
Base           = 0 if Impact <= 0
               = Roundup(min(Impact + Exploitability, 10))           S:U
               = Roundup(min(1.08 * (Impact + Exploitability), 10))  S:C
Temporal       = Roundup(Base * E * RL * RC)
```

Roundup returns the smallest one-decimal number equal to or above the input, computed on integers (x * 100000) to avoid float errors. Plain `round()` or `ceil(x*10)/10` gives wrong answers on some vectors.

## Temporal metrics

| Metric | Values (weight) |
|---|---|
| E Exploit Code Maturity | X (1), H High (1), F Functional (0.97), P Proof-of-concept (0.94), U Unproven (0.91) |
| RL Remediation Level | X (1), U Unavailable (1), W Workaround (0.97), T Temporary fix (0.96), O Official fix (0.95) |
| RC Report Confidence | X (1), C Confirmed (1), R Reasonable (0.96), U Unknown (0.92) |

## Environmental metrics

- Security requirements CR, IR, AR: H (1.5), M (1), L (0.5), X (1). Use them to say "this host's data barely matters" or "integrity is everything here"
- Modified base metrics (MAV, MAC, MPR, MUI, MS, MC, MI, MA): the base metric as it is in your deployment (a network bug only reachable from the internal network becomes `MAV:A` or `MAV:L` depending on how you see it; a control like a WAF never changes the metric unless it removes the attack path)
- Modified impact: `MISS = min(1 - (1 - CR*MC)(1 - IR*MI)(1 - AR*MA), 0.915)`. Scope changed uses `7.52*(MISS - 0.029) - 3.25*(MISS*0.9731 - 0.02)^13`

## Severity bands

| Score | Rating |
|---|---|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

## Reference vectors

| Vector | Score | Typical bug |
|---|---|---|
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Unauthenticated remote code execution |
| AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 | RCE that escapes its component |
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | Unauthenticated data leak |
| AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | Local privilege escalation |
| AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N | 6.4 | Stored XSS by a logged-in user |
| AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Reflected XSS |
| AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | 7.5 | Unauthenticated denial of service |

## Common scoring mistakes

- Scoring the worst case of the whole product instead of the vulnerable component
- Setting S:C for every web bug. Scope changes only when another authority is impacted (XSS hits the browser, so it is S:C; SQL injection into the app's own database is usually S:U)
- Using PR:N for a bug behind any login form that anyone can sign up for. Free self-signup is still PR:L
- Treating CVSS as risk. Exposure, exploitation in the wild and asset value decide the order; CVSS is one input
- Mixing 3.0 and 3.1 scores from different sources without noting it (3.1 changed the rounding and the environmental formula)
