# OWASP Top 10 for LLM Applications (2025)

Contents: LLM01 to LLM10; OWASP Agentic Top 10 2026; mapping scanner findings.

The 2025 list from the OWASP GenAI Security Project, with what each risk looks like in a tool-using agent and the controls that help. It is still the current LLM list (checked 2026-11-19). Check the official list at genai.owasp.org for the full text. The agentic list and a rule-id map are at the end.

| ID | Name |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

## LLM01 Prompt Injection

Input changes the model's behavior in ways the developer did not intend. Direct: the user types it. Indirect: it rides in on content the model reads (a web page, issue, email, file, tool result).

In agents: a README tells the coding agent to run a script; a web page tells a browsing agent to send the chat history to a URL; hidden text in a PDF changes a summary.

Controls:
- Assume any content can carry instructions. Keep untrusted content separate from instructions and label it as data
- Limit what a hijacked agent can do (LLM06): least-privilege tools, human approval for writes, sends and spends
- Strip hidden content before the model sees it (invisible Unicode, hidden HTML, comments)
- Block exfiltration channels: no rendering of images or links to arbitrary hosts in output
- Scanner rules: PI-001 to PI-008

## LLM02 Sensitive Information Disclosure

The model reveals personal data, credentials, business data or other users' data through its output.

In agents: the agent reads `.env` or `~/.aws/credentials` and echoes it into a reply, a commit, a log or a tool call.

Controls: keep secrets out of the agent's reach (deny rules, scoped directories, no inline keys in configs), redact in logs, filter output for secret patterns. Scanner rules: AGT-010, AGT-011, AGT-030.

## LLM03 Supply Chain

Third-party models, datasets, adapters, packages and plugins that are vulnerable, tampered with or malicious.

In agents: an MCP server pulled with `npx -y` at every start, a typosquatted tool package, a shared prompt or skill file with hidden instructions, a model downloaded from an unverified source.

Controls: pin versions, review MCP servers like any dependency, prefer official or well-maintained servers, verify model and dataset sources, keep an inventory. Scanner rules: AGT-040, AGT-043.

## LLM04 Data and Model Poisoning

Pre-training, fine-tuning or embedding data is manipulated to add backdoors, bias or vulnerabilities.

In agents: poisoned documents in a RAG knowledge base, planted examples in fine-tuning data, a shared memory that stores attacker text and replays it later.

Controls: track data provenance, validate and review what enters training sets and knowledge bases, limit who can write to agent memory, test models for unexpected triggers.

## LLM05 Improper Output Handling

Model output is passed to other components without validation, leading to XSS, SQL injection, command injection, SSRF and similar.

In agents: model output rendered as HTML in a web UI, used to build a shell command or SQL query, or used as a URL the server fetches.

Controls: treat model output like user input: encode for the context, use parameterized queries, never pass it to a shell or `eval`, allow-list URLs and image hosts.

## LLM06 Excessive Agency

The system grants the model more functionality, permissions or autonomy than the task needs, so a manipulated or wrong output causes real damage.

In agents: `bypassPermissions`, `Bash(*)`, a GitHub token with org-admin scope for a bot that only comments, an email tool that can send to anyone.

Controls: minimal tools, minimal permissions per tool, scoped credentials, human approval for high-impact actions, rate limits. Scanner rules: AGT-001, AGT-002, AGT-011, AGT-012, AGT-020.

## LLM07 System Prompt Leakage

The system prompt contains information that should not be exposed (credentials, internal rules, permission logic), and users can extract it.

Controls: never put secrets or access-control decisions in the prompt; enforce permissions outside the model; assume the prompt will be read.

## LLM08 Vector and Embedding Weaknesses

Weaknesses in how embeddings are generated, stored or retrieved in RAG: cross-tenant leakage, poisoned entries, embedding inversion.

Controls: per-tenant access control at retrieval time, validate sources before indexing, keep access logs, treat retrieved text as untrusted (it can carry LLM01 payloads).

## LLM09 Misinformation

The model produces false or misleading output that looks credible (hallucinations, invented packages, wrong citations), and people or systems rely on it.

In agents: a coding agent installs a package name it invented, which an attacker has since registered ("slopsquatting").

Controls: ground answers in sources, verify package names against the registry before install, human review for high-stakes output, show uncertainty.

## LLM10 Unbounded Consumption

Uncontrolled inference: denial of service, runaway cost ("denial of wallet"), or model extraction through heavy querying.

In agents: a loop that keeps calling tools, a sub-agent fan-out with no cap, a public endpoint without rate limits.

Controls: rate limits and quotas per user and key, max tokens and max steps per task, timeouts, budget alerts, monitoring.

## OWASP Top 10 for Agentic Applications (2026)

Published by the OWASP GenAI Security Project in December 2025 for agents that plan, use tools and act. Use it next to the LLM list when the system has tools, memory or other agents. Check names and text at genai.owasp.org (resource "OWASP Top 10 for Agentic Applications for 2026").

| ID | Name | Typical agent failure |
|---|---|---|
| ASI01 | Agent Goal Hijack | injected content changes what the agent is trying to do |
| ASI02 | Tool Misuse and Exploitation | a legitimate tool used in an unsafe way (deletes, sends, spends) |
| ASI03 | Identity and Privilege Abuse | the agent acts with broader credentials than the task needs, or inherits a user's |
| ASI04 | Agentic Supply Chain Vulnerabilities | poisoned MCP servers, plugins, tool descriptions or prompts loaded at run time |
| ASI05 | Unexpected Code Execution | generated or fetched code runs without review |
| ASI06 | Memory and Context Poisoning | bad data written to memory or RAG keeps steering later sessions |
| ASI07 | Insecure Inter-Agent Communication | spoofed or unauthenticated messages between agents |
| ASI08 | Cascading Failures | one agent's error or compromise spreads through a pipeline |
| ASI09 | Human-Agent Trust Exploitation | the agent's confident output gets a person to approve something harmful |
| ASI10 | Rogue Agents | an agent that drifts from or hides from its intended behavior |

## Mapping scanner findings

| Finding | LLM 2025 | Agentic 2026 |
|---|---|---|
| PI-001 to PI-008 | LLM01 Prompt Injection (PI-007 also LLM02, it is the way data leaves) | ASI01 |
| PI-009 (tool poisoning) | LLM01, LLM02 | ASI01, ASI04 |
| PI-010 (terminal escapes) | LLM01, LLM05 | ASI09 |
| AGT-001, AGT-002, AGT-003, AGT-011, AGT-012, AGT-013, AGT-020 | LLM06 Excessive Agency | ASI02, ASI03, ASI05 |
| AGT-010, AGT-030 | LLM02 Sensitive Information Disclosure | ASI03 |
| AGT-014 | LLM02 (keys and prompts sent to another host) | ASI03, ASI04 |
| AGT-040, AGT-043, AGT-044 | LLM03 Supply Chain | ASI04, ASI05 |
| AGT-041 | LLM02 (credentials and data in transit) | ASI07 |
