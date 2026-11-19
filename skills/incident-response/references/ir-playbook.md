# Incident response playbook

A short operating guide. Read it at the start of an incident and again before closing one.

## Phases

NIST SP 800-61 Rev. 2 describes the classic lifecycle: Preparation, Detection and Analysis, Containment / Eradication / Recovery, Post-Incident Activity. Rev. 3 (2025) maps the same work onto the CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover). In practice:

| Phase | Goal | Done when |
|---|---|---|
| Detect and triage | Decide if it is an incident and how bad | Type, severity and lead are set |
| Preserve | Keep the evidence | Volatile data collected and hashed, logs exported |
| Scope | Know every host, account and data set involved | Timeline from patient zero, list of IOCs |
| Contain | Stop the damage | Attacker access cut, spread stopped |
| Eradicate | Remove every foothold | Hosts rebuilt, persistence removed, credentials rotated |
| Recover | Back to normal, safely | Services restored from known-good, monitoring in place |
| Learn | Not again | Report written, fixes have owners and dates |

## Severity levels

| Level | Typical signs | Response |
|---|---|---|
| Critical | Active encryption, domain admin compromised, money leaving, large personal data breach | All hands now, leadership and legal informed within the hour |
| High | One server or admin account compromised, malware with C2, confirmed data exposure | Same day, incident lead assigned |
| Medium | Single user account taken over, contained malware, failed but targeted attack | Within one business day |
| Low | Policy violation, blocked phishing, suspicious but unconfirmed activity | Normal queue |

Raise the level as soon as scope grows. Never lower it before scope is confirmed.

## The first hour

1. Name one incident lead. Everyone else reports to them
2. Start the log: UTC time, who, what, why, approved by
3. Decide whether damage is ongoing. If yes, contain first (isolate, not power off)
4. Collect volatile evidence: memory, network connections, processes, sessions
5. Export logs from every system that might be involved, before rotation or an attacker clears them
6. Inform legal and, if you have one, the cyber insurer (many policies require notice before you hire responders or talk to the attacker)
7. Switch to out-of-band communication if email or chat may be compromised (phone, a separate Signal group, personal accounts)

## Do and don't

- Do isolate from the network; don't power off a running host you have not captured
- Do disable accounts; don't delete them (you lose their history and ownership)
- Do copy suspicious files into a password-protected zip; don't open them, and don't upload confidential files to public sandboxes
- Do rebuild compromised hosts; don't trust a "cleaned" one
- Do rotate credentials after the attacker is locked out, not before (they will watch you change them)
- Don't tip off the attacker: no messages from compromised mailboxes, no obvious changes until you are ready to contain everywhere at once
- Don't contact or pay the attacker without legal, insurer and law enforcement input

## Communication

- One source of truth (the incident log), one person speaking to customers or press
- Internal updates on a fixed rhythm (for example every 2 hours for critical), even when there is no news
- Say what you know, what you don't, and when the next update is. No guesses about attribution

## Notification deadlines (flag early, let legal decide)

| Regime | Who | Deadline |
|---|---|---|
| GDPR Art. 33 | Supervisory authority, for a personal data breach unless unlikely to result in a risk | 72 hours after becoming aware |
| GDPR Art. 34 | Affected people, when the risk to them is high | Without undue delay |
| NIS2 (EU, essential/important entities) | CSIRT or competent authority, significant incident | Early warning 24 h, notification 72 h, final report 1 month |
| SEC Form 8-K Item 1.05 (US public companies) | Investors | 4 business days after determining the incident is material |
| HIPAA Breach Notification Rule (US) | Affected individuals | Without unreasonable delay, no later than 60 days after discovery |

Contracts (customers, payment processors, cyber insurance) often add shorter deadlines. Check them on day one.

## Closing checklist

- Root cause known and fixed, not just the symptom
- Every IOC swept across the whole fleet
- Every credential the attacker could have seen rotated
- Backups confirmed clean and restorable
- Report written, follow-ups have owners and due dates
- Evidence archived with hashes and retention date
