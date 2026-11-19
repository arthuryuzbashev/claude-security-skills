# STRIDE threat and mitigation catalog

STRIDE was created at Microsoft by Loren Kohnfelder and Praerit Garg (1999). Each letter is the opposite of a security property:

| Letter | Threat | Property it breaks | Plain question |
|---|---|---|---|
| S | Spoofing | Authentication | Can someone pretend to be someone or something else? |
| T | Tampering | Integrity | Can someone change data or code they should not? |
| R | Repudiation | Non-repudiation (accountability) | Can someone deny they did it, and can we prove otherwise? |
| I | Information disclosure | Confidentiality | Can someone see data they should not? |
| D | Denial of service | Availability | Can someone stop it working for others? |
| E | Elevation of privilege | Authorization | Can someone do more than they are allowed to? |

## STRIDE per element

Not every letter applies to every element. This is the usual mapping and what `stride_model.py` uses:

| Element (DFD) | Component types in the model | S | T | R | I | D | E |
|---|---|---|---|---|---|---|---|
| External entity | user, external | yes | | yes | | | |
| Process | web, api, mobile, llm, service | yes | yes | yes | yes | yes | yes |
| Data store | db, storage, queue | | yes | (logs) | yes | yes | |
| Data flow | any flow that crosses a trust boundary | | yes | | yes | yes | |

Repudiation applies to a store only when it holds audit logs. The script folds that into the process R threat and the logging flag.

## Threat ids the script emits

| ID | Element | STRIDE | Threat | Typical mitigations |
|---|---|---|---|---|
| STR-S01 | process | S | Caller identity spoofed | Sessions or OIDC for users, mTLS or signed short-lived tokens for services, no IP-based trust |
| STR-T01 | process | T | Input tampering and injection | Allow-list schema validation, parameterized queries, context output encoding, no mass assignment |
| STR-R01 | process | R | Actions cannot be traced | Audit log of actor, action, target, time, source; append-only storage; clock sync |
| STR-I01 | process | I | Leaks through responses or errors | Explicit response schemas, generic error pages, ownership checks |
| STR-D01 | process | D | Resource exhaustion | Rate limits, timeouts, size caps, autoscaling with budget alarms |
| STR-E01 | process | E | Missing authorization | Deny by default, server-side role and object checks, tests with two accounts |
| WEB-T01 | web | T | Cross-site scripting | Output encoding, strict CSP, no raw HTML sinks |
| WEB-E01 | web | E | Cross-site request forgery | SameSite cookies, CSRF tokens or Origin checks |
| API-E01 | api | E | Broken object level authorization (OWASP API1:2023) | Scope every query by caller or tenant |
| MOB-I01 | mobile | I | Sensitive data on the device | Keychain / Keystore, no secrets in logs or backups |
| MOB-T01 | mobile | T | App modified or repackaged | All rules enforced server-side, attestation where it matters |
| LLM-T01 | llm | T | Prompt injection (OWASP LLM01) | Treat all input and retrieved text as untrusted, separate instructions from data, confirm risky actions |
| LLM-I01 | llm | I | Sensitive data disclosed by the model | No secrets in prompts, permission-filtered retrieval, output scanning |
| LLM-E01 | llm | E | Excessive agency | Least-privilege tools acting as the end user, allow-listed actions, human approval |
| LLM-D01 | llm | D | Cost and token exhaustion | Per-user quotas, length caps, agent loop limits, spend alerts |
| STR-T10 | store | T | Stored data tampered with | Least-privilege accounts, audit tables, tested backups |
| STR-I10 | store | I | Stored data disclosed | Encryption at rest, private network, per-service accounts, encrypted backups |
| STR-D10 | store | D | Store unavailable or lost | Replicas, point-in-time recovery, immutable backups, capacity alerts |
| STO-I01 | storage | I | Publicly readable objects | Account-level public access block, signed URLs |
| Q-S01 | queue | S | Forged messages | Authenticated producers, per-topic permissions, payload validation |
| Q-D01 | queue | D | Poison or flood messages | Consumer schema checks, size limits, dead-letter queues |
| STR-S20 | external | S | Entity impersonated | MFA, signed requests, webhook signature and timestamp checks |
| STR-R20 | external | R | Entity denies an action | Authenticated audit records, receipts |
| EXT-I01 | external | I | Sensitive data shared with a third party | DPA, data minimization, vendor assurance reports |
| STR-T30 | flow | T | Modified in transit | TLS 1.2+ with validation, mTLS, signed payloads |
| STR-I30 | flow | I | Read in transit | Encryption in transit, no secrets in URLs |
| STR-D30 | flow | D | Flow interrupted or flooded | Timeouts, retries with backoff, circuit breakers |

The OWASP references (API Security Top 10 2023, Top 10 for LLM Applications 2025) are named so you can look them up; the script does not depend on them.

## Design flags

Flags are specific problems in the model itself, not generic "this could happen" threats. Fix or explain every flag before the review ends.

| ID | Severity | Trigger |
|---|---|---|
| FLOW-001 | high (low for public data) | `auth: none` on a flow into a more trusted zone |
| FLOW-002 | high, critical when one end is a trust-0 zone and the flow crosses zones | sensitive data over a plaintext protocol or `encrypted: no` |
| FLOW-003 | medium | plaintext flow crosses a boundary (non-sensitive data) |
| FLOW-004 | low | boundary crossing into a more trusted zone with no `auth:` |
| FLOW-005 | low | sensitive data across a boundary with unknown encryption |
| FLOW-006 | high | trust-0 component talks straight to a data store |
| ELEM-001 | medium / low | `logging: no` (medium when it receives cross-zone traffic) or logging not stated on a cross-zone receiver |
| ELEM-002 | high | data store in a zone with trust 0 or 1 |
| ELEM-003 | info | component with no flows |

## Default likelihood and impact

Both are 1-3 so a session can move them quickly.

- Impact comes from the most sensitive data the element touches: public 1, internal or unclassified 2, confidential / pii / personal / financial 3, secrets / credentials / payment / pci / phi / health 3
- Likelihood is 3 for elements reachable from a trust-0 zone, 2 when they receive traffic from another zone, 1 otherwise. Specific rules raise it: unauthenticated inbound flows (spoofing), logging off (repudiation), plaintext flows (tampering and disclosure on the wire), an LLM that calls other components (excessive agency)
- Severity of a threat: L x I of 9 is high, 4-6 medium, 1-3 low. Threats never reach critical on defaults; only a FLOW-002 flag does

These are defaults to start the conversation. Change them when the team knows better, and write down why.

## Data classification labels the script understands

`public`, `none` (level 0) · `internal` (1, also the default) · `confidential`, `pii`, `personal`, `financial` (2) · `secret`, `secrets`, `credentials`, `payment`, `pci`, `phi`, `health`, `restricted` (3). Unknown labels count as internal.

## Protocols

Encrypted: https, tls, mtls, wss, sftp, ssh, ftps, grpcs, amqps, mqtts, ldaps, smtps, imaps, ipsec, wireguard, vpn, and any `<name>+tls`.
Plaintext: http, ws, ftp, telnet, amqp, mqtt, ldap, tcp, udp, smtp, imap, pop3, redis, memcached, snmp, syslog.
Anything else (postgres, mysql, grpc, kafka) is "unknown" because it may or may not negotiate TLS. Say `postgres+tls` or set `encrypted: yes|no` to remove the doubt.
