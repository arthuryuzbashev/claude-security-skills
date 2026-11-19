# Framework quick reference

Enough structure to talk about NIST CSF 2.0, ISO/IEC 27001:2022 and SOC 2 without opening the standards.
Always check the official text before quoting a control to an auditor.

## NIST Cybersecurity Framework 2.0 (February 2024)

Six functions, 22 categories, 106 subcategories (NIST CSWP 29, published 26 February 2024). Govern is new in 2.0 and sits across the other five.

| Function | Categories |
|---|---|
| GV Govern | GV.OC Organizational Context, GV.RM Risk Management Strategy, GV.RR Roles, Responsibilities, and Authorities, GV.PO Policy, GV.OV Oversight, GV.SC Cybersecurity Supply Chain Risk Management |
| ID Identify | ID.AM Asset Management, ID.RA Risk Assessment, ID.IM Improvement |
| PR Protect | PR.AA Identity Management, Authentication, and Access Control, PR.AT Awareness and Training, PR.DS Data Security, PR.PS Platform Security, PR.IR Technology Infrastructure Resilience |
| DE Detect | DE.CM Continuous Monitoring, DE.AE Adverse Event Analysis |
| RS Respond | RS.MA Incident Management, RS.AN Incident Analysis, RS.CO Incident Response Reporting and Communication, RS.MI Incident Mitigation |
| RC Recover | RC.RP Incident Recovery Plan Execution, RC.CO Incident Recovery Communication |

Vulnerability disclosure lives in ID.RA-08 (processes for receiving, analyzing and responding to disclosures).

Changes from 1.1 people trip over: PR.AC became PR.AA, physical access moved into PR.AA, PR.IP and PR.PT were folded
mostly into PR.PS and PR.IR, DE.DP and RS.IM/RC.IM were removed (improvement now lives in ID.IM), supply chain moved
from ID.SC to GV.SC. CSF is voluntary; use Profiles (current vs target) and Tiers (1 Partial to 4 Adaptive) to set goals.

## ISO/IEC 27001:2022

Certifiable management system. Clauses 4-10 are mandatory (context, leadership, planning incl. risk assessment
6.1.2 and treatment 6.1.3, support, operation, performance evaluation incl. internal audit 9.2 and management review 9.3,
improvement). Annex A lists 93 controls in four themes; you pick them through the Statement of Applicability (SoA)
and justify every exclusion.

| Theme | Range | Count | Examples |
|---|---|---|---|
| Organizational | 5.1-5.37 | 37 | 5.1 Policies, 5.9 Inventory of assets, 5.15 Access control, 5.19 Supplier relationships, 5.23 Cloud services, 5.24 Incident management planning, 5.30 ICT readiness for business continuity |
| People | 6.1-6.8 | 8 | 6.1 Screening, 6.3 Awareness, education and training, 6.7 Remote working, 6.8 Event reporting |
| Physical | 7.1-7.14 | 14 | 7.1 Physical perimeters, 7.2 Physical entry, 7.14 Secure disposal or re-use of equipment |
| Technological | 8.1-8.34 | 34 | 8.5 Secure authentication, 8.8 Technical vulnerabilities, 8.13 Backup, 8.15 Logging, 8.16 Monitoring, 8.24 Cryptography, 8.28 Secure coding |

Management review is clause 9.3, not an Annex A control. Do not map board or management oversight to 5.35
(Independent review of information security); 5.35 is the independent review (internal or external audit style).

New in 2022 (11): 5.7 Threat intelligence, 5.23 Cloud services, 5.30 ICT readiness for business continuity,
7.4 Physical security monitoring, 8.9 Configuration management, 8.10 Information deletion, 8.11 Data masking,
8.12 Data leakage prevention, 8.16 Monitoring activities, 8.23 Web filtering, 8.28 Secure coding.

## SOC 2 (AICPA Trust Services Criteria, 2017, points of focus revised 2022)

An attestation report by a CPA firm, not a certification. Type I: controls designed at a point in time.
Type II: controls operating over a period (usually 3-12 months), so you need evidence for the whole period.

| Category | Criteria | Notes |
|---|---|---|
| Security (Common Criteria, always in scope) | CC1 Control environment, CC2 Communication and information, CC3 Risk assessment, CC4 Monitoring activities, CC5 Control activities, CC6 Logical and physical access, CC7 System operations, CC8 Change management, CC9 Risk mitigation | CC1-CC5 follow the COSO principles |
| Availability | A1.1-A1.3 | Capacity, backup and recovery, recovery testing |
| Confidentiality | C1.1-C1.2 | Identify and protect, then dispose of confidential information |
| Processing Integrity | PI1.x | Complete, accurate, timely processing |
| Privacy | P1-P8 | Notice, choice, collection, use, access, disclosure, quality, monitoring |

Criteria used in `control_gap.py`: CC1.2 board oversight, CC1.3 structures and authorities, CC2.2 internal
communication, CC3.2 risk identification, CC4.1 ongoing and separate evaluations, CC5.3 policies and procedures,
CC6.1 logical access security, CC6.2 user registration and removal, CC6.3 role-based access, CC6.4 physical access,
CC6.5 disposal of assets, CC6.6 boundary protection, CC6.7 data transmission and movement, CC6.8 malicious software,
CC7.1 configuration and vulnerability detection, CC7.2 anomaly monitoring, CC7.3 event evaluation, CC7.4 incident
response, CC8.1 change management, CC9.1 business disruption, CC9.2 vendors and partners, A1.2 backup and recovery
infrastructure, A1.3 recovery testing, C1.1 identify confidential information, C1.2 dispose of confidential information.

## EU regulation (NIS2, DORA, CRA)

| Law | Who | Key dates | Core asks |
|---|---|---|---|
| NIS2, Directive (EU) 2022/2555 | Essential and important entities in 18 sectors (medium and large, plus some always in scope such as DNS and TLD providers) | Member State transposition deadline 17 Oct 2024; national laws apply from their own dates, check each country | Art. 20 management body approves and oversees measures, must train; Art. 21(2)(a)-(j) ten risk-management measures; Art. 23 reporting: early warning within 24h, notification within 72h, final report within one month |
| Implementing Regulation (EU) 2024/2690 | DNS, TLD, cloud, data centre, CDN, managed (security) service providers, marketplaces, search engines, social networks, trust services | Adopted October 2024 | Technical detail for Art. 21(2) in its Annex, sections 1 to 13 (policy, risk, incident handling, continuity, supply chain, acquisition and maintenance incl. 6.10 vulnerability handling, effectiveness, hygiene and training, crypto, HR, access, assets, physical) |
| DORA, Regulation (EU) 2022/2554 | EU financial entities and their critical ICT third-party providers | Applies from 17 Jan 2025 | ICT risk framework, major incident reporting, resilience testing (TLPT for some), third-party register and contract terms |
| Cyber Resilience Act, Regulation (EU) 2024/2847 | Makers of products with digital elements sold in the EU | Reporting duties from 11 Sep 2026; full application 11 Dec 2027 | Secure by design, vulnerability handling and coordinated disclosure, SBOM, security updates over the support period; report actively exploited vulnerabilities and severe incidents to CSIRT/ENISA (24h early warning) |

Art. 21(2) measures in short: (a) risk analysis and security policies, (b) incident handling, (c) business continuity,
backup and crisis management, (d) supply chain security, (e) security in acquisition, development and maintenance incl.
vulnerability handling and disclosure, (f) assessing effectiveness, (g) cyber hygiene and training, (h) cryptography,
(i) HR security, access control and asset management, (j) MFA and secured communications. `control_gap.py` maps
each control to these letters; controls with no NIS2 line (physical security, threat intelligence, DLP, privacy) are
still worth doing, they just have no direct article.

## Running a gap assessment

1. Agree scope: which entity, systems and frameworks (customers usually ask for SOC 2 in the US, ISO 27001 in Europe)
2. Answer `control_gap.py --template` with the people who run each control. "Partial" needs a note saying what is missing
3. Ask for evidence on every "yes" (a screenshot, an export, a ticket). No evidence means partial
4. Prioritize gaps by the script's severity, then by what the next customer or auditor will ask for first
5. Feed the gaps into the risk register as risks with owners and dates
