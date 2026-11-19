---
name: threat-modeling
description: Threat modeling for software designs with STRIDE. Turns a short system description (components such as web, api, db, queue, storage, mobile, llm, users and third parties, trust zones, and data flows with protocol, auth and data class) into STRIDE threats per element and per trust-boundary crossing, with default likelihood, impact and mitigations, flags for unauthenticated flows, plaintext sensitive data and missing logging, a markdown threat table and a Mermaid data-flow diagram with trust boundaries. Also diffs two versions of a design to list new flows and boundary crossings that need review. Use whenever someone mentions threat model, STRIDE, data flow diagram, DFD, trust boundary, attack surface, security design review, architecture review, "what could go wrong", "is this design secure", a new integration, webhook, AI agent or LLM feature, or wants security sign-off before building.
---

# Threat modeling

Find design flaws before they are code. Describe the system in a small file, generate the STRIDE threats and a diagram, then run a short session to decide what to do about each one.

## When to use

- A new feature, service, integration or LLM/agent capability is being designed
- Someone asks "is this architecture secure?" or wants a security design review
- A pentest or incident found something the team did not expect, and the design needs a second look
- A design changed and you want to know what is new to review (`model_diff.py`)
- Producing a threat model document or DFD for an audit, a customer or a compliance requirement

## Ground rules

- The output is a starting list, not a verdict. Generic STRIDE threats exist for every component; the flags are the specific problems. Read the flags first
- Model what is built or planned, not the ideal. If nobody knows how a flow authenticates, leave `auth` out and let the script flag it
- Defaults (likelihood, impact) are there to start the talk. Change them when the team knows better and write down why
- Keep real hostnames, IPs and secrets out of shared model files when they are not needed; component names are enough
- Defensive only: the output describes threats and fixes. Do not turn it into attack steps against a live system

## Workflow

1. Scope: one feature or service. Agree it with the tech lead
2. Write the model file (template in `references/session-guide.md`, examples in `examples/`). Components, zones with trust 0-3, flows with protocol, auth and data
3. Run `stride_model.py model.yaml --output threat-model.md --fail-on never`
4. Fix the model where the flags say "not stated" and re-run
5. Run the session on the four questions (`references/session-guide.md`): confirm the diagram, walk flags then threats by severity, add business logic threats the catalog cannot know
6. Give every flag and high threat a state: mitigated, to do (owner, date), accepted (who), not applicable (why)
7. Keep the model next to the code. On the next design change run `model_diff.py old.yaml new.yaml` and review what it lists

## Tools

### stride_model.py

Reads JSON or a simple YAML subset. Outputs a Markdown report (summary, Mermaid DFD, design flags, STRIDE threat table, assumptions), JSON, or just the diagram.

```bash
python3 scripts/stride_model.py examples/checkout_v2.yaml
python3 scripts/stride_model.py examples/checkout_v2.yaml --output threat-model.md --fail-on never
python3 scripts/stride_model.py examples/checkout_v2.yaml --mermaid-only > dfd.mmd
python3 scripts/stride_model.py examples/minimal.json --json
cat model.yaml | python3 scripts/stride_model.py -
```

Model format:

- `zones`: `name: trust` (0 internet or third party, 1 dmz or partner, 2 internal, 3 restricted data). Common names (internet, dmz, internal, data...) get a default; unknown names get 2 with a warning
- `components`: `id`, `type` (user, external, web, api, mobile, llm, service, db, storage, queue), `zone`, optional `name`, `logging: yes|no`
- `flows`: `from`, `to`, optional `id`, `protocol`, `auth` (`none` = unauthenticated, missing = unknown), `encrypted: yes|no` (otherwise read from the protocol), `data` (one label or a list: public, internal, confidential, pii, personal, financial, secrets, credentials, payment, pci, phi, health)

Element threats follow STRIDE-per-element (external S R, process S T R I D E, store T I D) plus type-specific ones (web XSS and CSRF, API object-level authorization, mobile, LLM prompt injection, disclosure, excessive agency and cost, storage, queue). Flows that cross a zone get T I D.
Design flags: FLOW-001 unauthenticated flow into a more trusted zone, FLOW-002 sensitive data in plaintext (critical across a trust-0 boundary), FLOW-003 plaintext boundary crossing, FLOW-004 auth not stated, FLOW-005 encryption not stated for sensitive data, FLOW-006 store reached straight from a trust-0 zone, ELEM-001 logging off or not stated, ELEM-002 store in a low-trust zone, ELEM-003 component with no flows.
Likelihood and impact are 1-3; threat severity is high at 9, medium at 4-6, low at 1-3. Details and every id in `references/stride-catalog.md`.

The diagram draws one subgraph per zone (with its trust level), shapes by type (stadium for users, cylinder for stores, double box for queues) and red arrows for flows with a medium or worse flag.

JSON: `{name, summary: {components, flows, boundary_crossings, flags, threats, by_severity}, warnings, findings: [{id, severity, title, detail, fix, location, kind: flag|threat, stride, likelihood, impact}], mermaid, flows: [{key, from, to, from_zone, to_zone, crosses_boundary, inbound, encrypted, authenticated, data_level, sensitive, ...}]}`.

### model_diff.py

Compares an old and a new model. Flows match by `id`, or by `from->to` when they have none (give flows ids so renames do not look like add plus remove).

```bash
python3 scripts/model_diff.py examples/checkout_v1.yaml examples/checkout_v2.yaml
python3 scripts/model_diff.py old.yaml new.yaml --json --fail-on medium
```

Findings:

- DIFF-001 new flow crossing a trust boundary (high when unauthenticated inbound or plaintext sensitive, else medium)
- DIFF-002 new flow inside a zone (medium if plaintext sensitive, else low)
- DIFF-003 changed flow: auth removed or no longer stated, encryption lost, data class raised, endpoints changed, now crosses a boundary
- DIFF-004 new component (medium for users, externals, LLMs or trust-0 zones)
- DIFF-005 component moved zone or changed type (high when a store moves to a lower-trust zone)
- DIFF-006 logging turned off
- DIFF-007 component or flow removed (info, with a decommission reminder)

JSON: `{old, new, findings: [{id, severity, title, detail, fix, location, change: added|changed|removed}], needs_review: [flow keys], summary: {added, changed, removed, boundary_flows_to_review, by_severity}}`.

Both tools: exit `0` nothing at or above `--fail-on` (default `high`), `1` something at or above it, `2` bad input (unknown component in a flow, bad type, duplicate id, unreadable file). Use `--fail-on never` for report-only runs and `model_diff.py` with the default in CI to trigger a review.

## Output

Hand back, in this order:

1. One line: components, flows, boundary crossings, flags by severity
2. The Mermaid diagram
3. Design flags table (severity, id, where, issue, fix)
4. Top threats (high first) with mitigation and a proposed state
5. Open questions for the team (anything "not stated")
6. For a diff: the flows to review and the weakened controls, before anything else

Keep the full threat table in the file, not in chat, when it is longer than about 20 rows.

## References

- `references/stride-catalog.md` the STRIDE letters, STRIDE-per-element, every threat and flag id with mitigations, how likelihood and impact are set, accepted data labels and protocols. Open it when explaining a threat or tuning scores
- `references/session-guide.md` running the session on the four questions, timings, threat states, when to model again, a model file template and a notes table. Open it before facilitating
