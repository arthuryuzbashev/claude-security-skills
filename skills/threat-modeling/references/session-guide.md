# Running a threat modeling session

The session follows Adam Shostack's four questions (also the backbone of the Threat Modeling Manifesto):

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?

Keep it to 60-90 minutes per system or feature. Bring an engineer who built it, someone who runs it, and someone from security. A product owner helps with question 3.

## Before the session (15 minutes)

- Pick the scope: one feature, one service or one release. "The whole platform" never finishes
- Draft the model file from the architecture doc or a quick chat with the tech lead
- Run `stride_model.py model.yaml --output threat-model.md --fail-on never` and skim the flags
- If there is a previous model, run `model_diff.py old.yaml new.yaml` and focus the session on what changed

## 1. What are we working on? (15-20 minutes)

Show the Mermaid diagram and walk it left to right.

- Is every component there? Ask about admin tools, batch jobs, CI/CD, monitoring and third-party SDKs; they are the usual misses
- Are the zones right? A zone is a place where everything inside trusts each other the same way. A new zone starts where authentication or network control changes
- For each flow crossing a zone: protocol, how the caller authenticates, what data it carries
- Mark data classes honestly. If a flow "sometimes" carries personal data, it carries personal data

Fix the model file live and re-run the script. "Not stated" flags (FLOW-004, FLOW-005, ELEM-001 low) mostly disappear here.

## 2. What can go wrong? (25-30 minutes)

Work through the flags first, then the STRIDE table from the highest severity down.

- Ask "how would this happen here?" for each threat. If nobody can describe a realistic path, mark it not applicable with a one-line reason
- Add threats the catalog cannot know: business logic abuse (refund loops, coupon stacking), insider misuse, supply chain, fraud
- For LLM components, ask what untrusted text reaches the prompt (user chat, uploaded files, web pages, tool results) and what the model can call
- Adjust likelihood and impact when the team has better information. Write the reason in the notes

Avoid: debating whether something is "really" spoofing or tampering. The letter only helps find threats; it does not change the fix.

## 3. What are we going to do about it? (15-20 minutes)

Every threat ends in one of four states:

| State | Needs |
|---|---|
| Mitigated | The control that exists today and how you know it works (test, config, report) |
| To do | Owner, ticket, due date. High findings get a date in the current or next sprint |
| Accepted | Name of the person with authority to accept, reason, review date |
| Not applicable | One-line reason |

Prefer fixes that remove a whole class of threat (put an authenticating API in front of the store, turn on mTLS for the mesh) over point fixes.

## 4. Did we do a good enough job? (5-10 minutes)

- Does every flag have a state? Does every high threat have an owner?
- Did we cover every boundary crossing in the diagram?
- Would a new engineer understand the diagram without us in the room?
- What did we skip because of time? Book a follow-up for it
- After the fixes ship: re-run the script, check that the flags are gone, and keep the model file next to the code so the next change can be diffed

## When to model again

- A new external integration, a new public endpoint or a new trust zone
- A new data class (payments, health, children's data)
- An LLM or agent gets a new tool or data source
- After an incident or a pentest finding that the model did not predict
- `model_diff.py` in CI on the model file is a cheap trigger: a non-zero exit means "book a session"

## Model file template

```yaml
name: Feature or system name
zones:
  internet: 0
  dmz: 1
  app: 2
  data: 3
components:
  - id: user
    type: user          # user, external, web, api, mobile, llm, service, db, storage, queue
    zone: internet
  - id: api
    name: Public API
    type: api
    zone: app
    logging: yes
flows:
  - id: login
    from: user
    to: api
    protocol: https
    auth: none          # session, oauth, mtls, apikey, iam, password, none
    data: [credentials]
```

## Notes template

| Threat / flag | State | Control or plan | Owner | Due | Notes |
|---|---|---|---|---|---|
| FLOW-001 chat | To do | Require the shop session on the support chat | dev-lead | 2026-12-15 | Anonymous chat dropped from scope |
