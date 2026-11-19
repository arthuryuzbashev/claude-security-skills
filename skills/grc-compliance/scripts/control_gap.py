#!/usr/bin/env python3
"""Turn yes/partial/no answers on common security controls into framework coverage and a gap list.

Each control maps to NIST CSF 2.0 categories, ISO/IEC 27001:2022 Annex A controls,
SOC 2 Trust Services Criteria and EU NIS2 (Directive 2022/2555) Articles 20, 21(2) and 23. The mapping is a starting point for a gap assessment,
not audit advice: coverage only counts the framework items this list touches.

Usage:
  control_gap.py answers.txt
  control_gap.py answers.json --json
  control_gap.py --template > answers.txt      # blank answers file with every question
  control_gap.py --list                        # the full mapping table
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
DISCLAIMER = ("Mappings are a starting point for a gap assessment, not audit advice or a certification opinion. "
              "Coverage counts only the framework items these controls touch (for example a subset of the 93 "
              "ISO/IEC 27001:2022 Annex A controls); check every gap against the framework text and your auditor.")
CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}
CSF_CATEGORIES = {
    "GV.OC": "Organizational Context", "GV.RM": "Risk Management Strategy",
    "GV.RR": "Roles, Responsibilities, and Authorities", "GV.PO": "Policy", "GV.OV": "Oversight",
    "GV.SC": "Cybersecurity Supply Chain Risk Management", "ID.AM": "Asset Management", "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement", "PR.AA": "Identity Management, Authentication, and Access Control",
    "PR.AT": "Awareness and Training", "PR.DS": "Data Security", "PR.PS": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience", "DE.CM": "Continuous Monitoring", "DE.AE": "Adverse Event Analysis",
    "RS.MA": "Incident Management", "RS.AN": "Incident Analysis", "RS.CO": "Incident Response Reporting and Communication",
    "RS.MI": "Incident Mitigation", "RC.RP": "Incident Recovery Plan Execution", "RC.CO": "Incident Recovery Communication",
}

# key, title, question, priority, CSF 2.0 categories, ISO 27001:2022 Annex A, SOC 2 TSC, fix
CONTROLS: List[Dict[str, Any]] = [dict(zip(("key", "title", "question", "priority", "csf", "iso", "soc2", "fix"), c)) for c in [
    ("mfa", "Multi-factor authentication",
     "Is MFA enforced for email, remote access, cloud consoles and all admin accounts?", "critical",
     ["PR.AA"], ["8.5"], ["CC6.1", "CC6.6"],
     "Enforce phishing-resistant MFA (passkeys, FIDO2) for admins and remote access first, then every user."),
    ("asset_inventory", "Asset inventory",
     "Is there a maintained inventory of hardware, software, cloud accounts and data stores with owners?", "high",
     ["ID.AM"], ["5.9"], ["CC6.1"],
     "Build the inventory from MDM, cloud APIs and the IdP; give every asset an owner and review it quarterly."),
    ("central_logging", "Security logging",
     "Are security-relevant logs (auth, admin actions, cloud audit, endpoints) collected centrally and kept 90+ days?", "high",
     ["PR.PS", "DE.CM"], ["8.15"], ["CC7.2"],
     "Ship IdP, cloud audit, endpoint and server auth logs to one store with retention and access control."),
    ("monitoring_alerting", "Monitoring and alerting",
     "Are alerts reviewed by a named person or service every day, including weekends?", "high",
     ["DE.CM", "DE.AE"], ["8.16"], ["CC7.2", "CC7.3"],
     "Define the alerts that matter, route them to an on-call rota or MDR provider, track response times."),
    ("backups", "Backups",
     "Are critical systems backed up, with at least one copy offline or immutable, and restores tested in the last 12 months?", "critical",
     ["PR.DS", "RC.RP"], ["8.13"], ["A1.2", "A1.3"],
     "Follow 3-2-1 with an immutable or offline copy, separate backup credentials, and a recorded restore test."),
    ("encryption_at_rest", "Encryption at rest",
     "Are laptops, databases, object storage and backups encrypted at rest?", "high",
     ["PR.DS"], ["8.24"], ["CC6.1"],
     "Turn on full-disk encryption via MDM and default encryption on cloud storage and databases; manage keys in a KMS."),
    ("encryption_in_transit", "Encryption in transit",
     "Is all external and internal traffic carrying sensitive data encrypted (TLS 1.2+)?", "high",
     ["PR.DS"], ["8.24"], ["CC6.7"],
     "Force TLS 1.2+ with HSTS on public sites; encrypt internal service and database connections too."),
    ("vuln_management", "Vulnerability management",
     "Are systems scanned for vulnerabilities and patched within defined deadlines (e.g. critical in 14 days)?", "critical",
     ["ID.RA", "PR.PS"], ["8.8"], ["CC7.1"],
     "Scan internal and external assets at least monthly, set patch SLAs by severity, report overdue items."),
    ("ir_plan", "Incident response plan",
     "Is there a written incident response plan with roles and contacts, exercised in the last 12 months?", "high",
     ["RS.MA", "ID.IM"], ["5.24", "5.26"], ["CC7.3", "CC7.4"],
     "Write a short plan (who decides, who to call, legal and customer notice), then run a tabletop exercise."),
    ("security_awareness", "Security awareness training",
     "Do all staff get security awareness training at hiring and at least yearly, including phishing?", "high",
     ["PR.AT"], ["6.3"], ["CC2.2"],
     "Run short yearly training plus phishing simulations; track completion and give extra training to admins."),
    ("access_reviews", "Access reviews",
     "Are user and admin access rights reviewed at least quarterly for key systems, with evidence kept?", "high",
     ["PR.AA"], ["5.18"], ["CC6.2", "CC6.3"],
     "Export access lists for key systems each quarter, have owners confirm or remove, keep the signed export."),
    ("vendor_risk", "Vendor risk management",
     "Are suppliers that handle your data or systems assessed before onboarding and reviewed on a schedule?", "medium",
     ["GV.SC"], ["5.19", "5.20"], ["CC9.2"],
     "Keep a vendor list ranked by data access, collect SOC 2 / ISO certificates or questionnaires, add security clauses."),
    ("privileged_access", "Privileged access",
     "Are admin rights limited to named people, separate from daily accounts, and logged?", "high",
     ["PR.AA"], ["8.2"], ["CC6.3"],
     "Use separate admin accounts or just-in-time elevation, remove standing admin rights, log admin sessions."),
    ("joiner_mover_leaver", "Joiner, mover, leaver process",
     "Is access removed on the last working day and adjusted when people change roles?", "high",
     ["PR.AA"], ["5.18", "6.5"], ["CC6.2"],
     "Drive provisioning from HR through the IdP (SSO + SCIM) so leaving disables every connected account."),
    ("security_policy", "Information security policy",
     "Is there an approved information security policy, reviewed yearly and known to staff?", "medium",
     ["GV.PO"], ["5.1"], ["CC5.3"],
     "Write a short top-level policy plus topic policies (access, acceptable use, incident), approve and publish them."),
    ("security_roles", "Security roles and responsibilities",
     "Is a named person accountable for security, with defined responsibilities for system owners?", "medium",
     ["GV.RR"], ["5.2"], ["CC1.3"],
     "Name the security lead, write down who owns which systems and data, and give them time to do it."),
    ("risk_assessment", "Risk assessment",
     "Is a security risk assessment done at least yearly and after major changes, with a risk register?", "high",
     ["ID.RA", "GV.RM"], [], ["CC3.2"],
     "Keep a risk register with owners and treatment (see risk_register.py). ISO 27001 requires this in clauses 6.1.2 and 8.2, not Annex A."),
    ("endpoint_protection", "Endpoint protection",
     "Do all servers and laptops run anti-malware or EDR that is centrally monitored?", "high",
     ["DE.CM", "PR.PS"], ["8.7"], ["CC6.8"],
     "Deploy EDR to every endpoint and server, alert on disabled agents, review detections daily."),
    ("secure_configuration", "Secure configuration baselines",
     "Are systems built from hardened baselines (e.g. CIS Benchmarks) and checked for drift?", "medium",
     ["PR.PS"], ["8.9"], ["CC7.1"],
     "Pick baselines for OS, cloud and SaaS, apply them as code or MDM profiles, scan for drift."),
    ("change_management", "Change management",
     "Are production changes reviewed, approved and traceable?", "medium",
     ["PR.PS"], ["8.32"], ["CC8.1"],
     "Require peer review and CI checks for production changes; keep the ticket or PR as the record."),
    ("network_security", "Network security",
     "Are inbound services limited to what is needed, with firewalls or security groups reviewed?", "medium",
     ["PR.IR"], ["8.20"], ["CC6.6"],
     "Default-deny inbound rules, no admin ports open to the internet, review rules quarterly."),
    ("network_segmentation", "Network segmentation",
     "Are production, corporate and guest networks separated, with sensitive systems isolated?", "medium",
     ["PR.IR"], ["8.22"], ["CC6.6"],
     "Separate production from office networks, isolate payment and admin systems, restrict east-west traffic."),
    ("secure_sdlc", "Secure development",
     "Do in-house apps follow secure coding rules with code review, dependency and secret scanning?", "medium",
     ["PR.PS"], ["8.25", "8.28", "8.29"], ["CC8.1"],
     "Add SAST, dependency and secret scanning in CI, require reviews, train developers on the OWASP Top 10."),
    ("data_classification", "Data classification",
     "Is data classified (e.g. public, internal, confidential) and do people know how to handle each class?", "medium",
     ["ID.AM", "PR.DS"], ["5.12"], ["C1.1"],
     "Define 3-4 classes with handling rules, label the main data stores, include it in training."),
    ("business_continuity", "Business continuity and disaster recovery",
     "Are recovery plans with RTO/RPO defined for critical services and tested?", "medium",
     ["RC.RP", "PR.IR"], ["5.29", "5.30"], ["A1.2", "A1.3", "CC9.1"],
     "Set RTO/RPO per critical service, document recovery steps, test a failover or restore yearly."),
    ("physical_security", "Physical security",
     "Are offices and server rooms access-controlled, with visitor logs?", "low",
     ["PR.AA"], ["7.1", "7.2"], ["CC6.4"],
     "Badge access to offices and equipment rooms, visitor sign-in and escort, review badge lists."),
    ("secure_disposal", "Secure disposal",
     "Are disks and devices wiped or destroyed before disposal or reuse, with records?", "low",
     ["ID.AM"], ["7.14", "8.10"], ["CC6.5", "C1.2"],
     "Wipe or destroy media through a certified provider and keep certificates of destruction."),
    ("secrets_management", "Secrets and password management",
     "Are passwords in a password manager and application secrets in a vault, never in code or chat?", "high",
     ["PR.AA"], ["5.17"], ["CC6.1"],
     "Roll out a company password manager, move app secrets to a vault, scan repositories for leaked secrets."),
    ("threat_intelligence", "Threat intelligence",
     "Do you follow advisories relevant to your stack (vendor bulletins, CISA KEV, sector ISAC)?", "low",
     ["ID.RA"], ["5.7"], [],
     "Subscribe to vendor and government advisories and the CISA KEV catalog; feed them into patch priorities."),
    ("security_testing", "Security testing",
     "Are penetration tests or equivalent assessments done at least yearly and after major changes?", "medium",
     ["ID.RA", "ID.IM"], ["8.8", "8.29"], ["CC4.1"],
     "Commission a yearly pentest of internet-facing systems and track findings to closure with retests."),
    ("data_loss_prevention", "Data leakage prevention",
     "Are there controls against sensitive data leaving (sharing settings, DLP rules, USB limits)?", "medium",
     ["PR.DS"], ["8.12"], ["CC6.7"],
     "Restrict external sharing in SaaS, add DLP rules for the most sensitive data, limit removable media."),
    ("cloud_security", "Cloud security configuration",
     "Are cloud accounts configured to a baseline (no public storage, audit logging on, least-privilege IAM)?", "high",
     ["PR.PS"], ["5.23"], ["CC6.1"],
     "Turn on the provider's posture checks, block public storage by default, review IAM for wildcard permissions."),
    ("hr_security", "HR security",
     "Are staff screened as appropriate before hiring and do contracts include security duties after leaving?", "low",
     ["GV.RR"], ["6.1", "6.2", "6.5"], [],
     "Add proportionate background checks and confidentiality clauses that last after employment ends."),
    ("incident_reporting", "Staff incident reporting",
     "Do staff know how to report a suspected incident or phishing email quickly?", "medium",
     ["RS.MA"], ["6.8"], [],
     "Give one easy channel (report-phish button, security email), confirm reports, thank reporters."),
    ("management_oversight", "Management oversight",
     "Does leadership review security status, risks and incidents at least twice a year?", "medium",
     ["GV.OV"], [], ["CC1.2"],
     "Put security on the leadership agenda with a short dashboard: top risks, incidents, overdue fixes. "
     "ISO 27001 requires this as the management review in clause 9.3, not Annex A."),
    ("endpoint_devices", "Managed endpoint devices",
     "Are laptops and phones that access company data enrolled in device management with screen lock and updates?", "medium",
     ["PR.PS"], ["8.1", "6.7"], [],
     "Enroll devices in MDM, enforce OS updates, encryption and screen lock, block unmanaged devices from SSO."),
    ("legal_privacy", "Legal, regulatory and privacy requirements",
     "Do you keep a list of legal, contractual and privacy obligations (e.g. GDPR) and who meets each?", "medium",
     ["GV.OC"], ["5.31", "5.34"], [],
     "List the laws, contracts and certifications that apply, assign owners, review yearly."),
    ("incident_notification", "Regulatory incident notification",
     "Do you know which incidents must be reported to regulators, CSIRTs or customers and by when "
     "(e.g. NIS2 24h early warning, 72h notification, 1 month final report; GDPR 72h), and who files them?", "high",
     ["RS.CO"], ["5.5", "5.24", "5.26"], ["CC2.3", "CC7.4"],
     "Write down each reporting duty with its clock, recipient and owner; add the forms and contacts to the IR plan "
     "and practise a notification in the next tabletop."),
    ("vuln_disclosure", "Vulnerability disclosure",
     "Can outsiders report vulnerabilities (security.txt, disclosure policy) and are their reports triaged and fixed?",
     "medium",
     ["ID.RA"], ["8.8"], ["CC2.3", "CC7.1"],
     "Publish a disclosure policy and /.well-known/security.txt, route reports to a tracked queue, reply within days. "
     "The EU Cyber Resilience Act makes this mandatory for products with digital elements."),
    ("software_supply_chain", "Software supply chain and SBOM",
     "For software you build or ship, do you know its third-party components (SBOM), keep them updated and "
     "protect the build pipeline?", "medium",
     ["GV.SC", "ID.AM"], ["5.21", "8.28"], ["CC8.1", "CC9.2"],
     "Generate an SBOM in CI (CycloneDX or SPDX), alert on vulnerable dependencies, pin and review third-party "
     "build actions, and restrict who can publish releases."),
]]
# EU NIS2 (Directive 2022/2555): Art.20 governance, Art.21(2)(a)-(j) risk-management measures, Art.23 reporting.
# Letters follow Art.21(2); the section in the comment is the matching part of the Annex to Implementing Regulation
# (EU) 2024/2690, which sets the detailed measures for digital infrastructure and digital provider entities.
NIS2 = {
    "mfa": ["Art.21(2)(j)"],                                  # 11 access control (MFA)
    "asset_inventory": ["Art.21(2)(i)"],                      # 12 asset management
    "central_logging": ["Art.21(2)(b)"],                      # 3 monitoring and logging
    "monitoring_alerting": ["Art.21(2)(b)"],                  # 3 event reporting
    "backups": ["Art.21(2)(c)"],                              # 4 backup and redundancy
    "encryption_at_rest": ["Art.21(2)(h)"],                   # 9 cryptography
    "encryption_in_transit": ["Art.21(2)(h)"],
    "vuln_management": ["Art.21(2)(e)"],                      # 6 patch management, 6.10 vulnerabilities
    "ir_plan": ["Art.21(2)(b)"],                              # 3 incident handling
    "security_awareness": ["Art.21(2)(g)", "Art.20"],         # 8 cyber hygiene and training; Art.20(2) management training
    "access_reviews": ["Art.21(2)(i)"],                       # 11 access control
    "vendor_risk": ["Art.21(2)(d)"],                          # 5 supply chain security
    "privileged_access": ["Art.21(2)(i)"],
    "joiner_mover_leaver": ["Art.21(2)(i)"],                  # 10 HR security, 11 access control
    "security_policy": ["Art.21(2)(a)"],                      # 1 security policy
    "security_roles": ["Art.20", "Art.21(2)(a)"],             # 1 roles and responsibilities
    "risk_assessment": ["Art.21(2)(a)"],                      # 2 risk management policy
    "endpoint_protection": ["Art.21(2)(e)"],                  # 6.9 protection against malicious software
    "secure_configuration": ["Art.21(2)(e)"],                 # 6 configuration management
    "change_management": ["Art.21(2)(e)"],                    # 6 change management
    "network_security": ["Art.21(2)(e)"],                     # 6.7 network security
    "network_segmentation": ["Art.21(2)(e)"],                 # 6.8 network segmentation
    "secure_sdlc": ["Art.21(2)(e)"],                          # 6 secure development life cycle
    "data_classification": ["Art.21(2)(i)"],                  # 12 asset classification
    "business_continuity": ["Art.21(2)(c)"],                  # 4 business continuity and crisis management
    "secure_disposal": ["Art.21(2)(i)"],                      # 12 asset handling and disposal
    "secrets_management": ["Art.21(2)(i)"],                   # 11 authentication
    "security_testing": ["Art.21(2)(e)", "Art.21(2)(f)"],     # 6 security testing, 7 effectiveness
    "cloud_security": ["Art.21(2)(e)"],
    "hr_security": ["Art.21(2)(i)"],                          # 10 human resources security
    "incident_reporting": ["Art.21(2)(b)"],
    "management_oversight": ["Art.20", "Art.21(2)(f)"],       # management approves and oversees the measures
    "endpoint_devices": ["Art.21(2)(g)"],                     # 8 basic cyber hygiene
    "incident_notification": ["Art.23"],
    "vuln_disclosure": ["Art.21(2)(e)"],                      # 6.10 vulnerability handling and disclosure
    "software_supply_chain": ["Art.21(2)(d)", "Art.21(2)(e)"],
}
for _c in CONTROLS:
    _c["nis2"] = NIS2.get(_c["key"], [])
for _n, _c in enumerate(CONTROLS, 1):
    _c["code"] = f"CTL-{_n:02d}"
BY_KEY = {c["key"]: c for c in CONTROLS}
BY_CODE = {c["code"].lower(): c for c in CONTROLS}
ANSWER_WORDS = {
    "yes": "yes", "y": "yes", "true": "yes", "implemented": "yes", "done": "yes", "full": "yes",
    "partial": "partial", "partially": "partial", "part": "partial", "in-progress": "partial", "in_progress": "partial",
    "no": "no", "n": "no", "false": "no", "missing": "no", "none": "no",
    "na": "na", "n/a": "na", "not-applicable": "na", "not_applicable": "na",
}
SCORES = {"yes": 1.0, "partial": 0.5, "no": 0.0}
FRAMEWORKS = [("csf", "NIST CSF 2.0"), ("iso", "ISO/IEC 27001:2022 Annex A"), ("soc2", "SOC 2 TSC"),
              ("nis2", "EU NIS2 Art. 20, 21(2), 23")]


def lookup(name: str) -> Optional[Dict[str, Any]]:
    n = name.strip().lower().replace(" ", "_").replace("-", "_")
    return BY_KEY.get(n) or BY_CODE.get(name.strip().lower())


def normalize_answer(value: Any) -> Optional[str]:
    v = str(value).strip().lower()
    v = v.replace("not applicable", "na").replace("in progress", "in-progress")
    return ANSWER_WORDS.get(v)


def parse_answers(text: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """Parse JSON, CSV (control,answer[,note]) or `control: answer  note` lines. Returns (answers, warnings)."""
    answers: Dict[str, Dict[str, str]] = {}
    warnings: List[str] = []
    stripped = text.strip()
    rows: List[Tuple[str, str, str, str]] = []  # (where, control, answer, note)
    if stripped.startswith("{"):
        data = json.loads(stripped)
        for k, v in data.items():
            if isinstance(v, dict):
                rows.append((k, k, str(v.get("answer", "")), str(v.get("note", ""))))
            else:
                rows.append((k, k, str(v), ""))
    elif stripped and re.match(r"^\s*control\s*,", stripped.splitlines()[0], re.I):
        for n, row in enumerate(csv.DictReader(io.StringIO(stripped)), 2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            rows.append((f"line {n}", row.get("control", ""), row.get("answer", ""), row.get("note", "")))
    else:
        for n, line in enumerate(stripped.splitlines(), 1):
            body = line.split("#", 1)[0].strip() if line.lstrip().startswith("#") else line.strip()
            if not body:
                continue
            m = re.match(r"^([\w.-]+)\s*[:=]\s*(\S*)\s*(.*)$", body)
            if not m:
                raise ValueError(f"line {n}: expected 'control: yes|partial|no|na', got {body!r}")
            note = m.group(3).lstrip("-#/ ").strip()
            rows.append((f"line {n}", m.group(1), m.group(2), note))
    for where, name, raw_answer, note in rows:
        ctl = lookup(name)
        if not ctl:
            warnings.append(f"{where}: unknown control {name!r} ignored (see --list)")
            continue
        if not raw_answer.strip() or raw_answer.strip() == "?":
            continue  # left blank in the template
        ans = normalize_answer(raw_answer)
        if not ans:
            raise ValueError(f"{where}: answer {raw_answer!r} for {name} must be yes, partial, no or na")
        if ctl["key"] in answers:
            warnings.append(f"{where}: {ctl['key']} answered twice, the last answer wins")
        answers[ctl["key"]] = {"answer": ans, "note": note}
    return answers, warnings


def _lower(severity: str) -> str:
    return SEVERITY_ORDER[max(0, SEVERITY_ORDER.index(severity) - 1)]


def assess(answers: Dict[str, Dict[str, str]], include_unanswered: bool = True) -> Dict[str, Any]:
    """Compute per-framework coverage and the prioritized gap list."""
    status = {}
    for c in CONTROLS:
        a = answers.get(c["key"])
        if a:
            status[c["key"]] = a["answer"]
        else:
            status[c["key"]] = "no" if include_unanswered else "na"

    coverage = {}
    for fw, label in FRAMEWORKS:
        items: Dict[str, List[float]] = {}
        for c in CONTROLS:
            for ref in c[fw]:
                bucket = items.setdefault(ref, [])
                if status[c["key"]] != "na":
                    bucket.append(SCORES[status[c["key"]]])
        scored = {ref: sum(v) / len(v) for ref, v in items.items() if v}
        pct = round(100 * sum(scored.values()) / len(scored), 1) if scored else None
        entry = {"framework": label, "items_mapped": len(items), "items_assessed": len(scored),
                 "coverage_pct": pct,
                 "full": sorted(r for r, s in scored.items() if s == 1.0),
                 "partial": sorted(r for r, s in scored.items() if 0 < s < 1),
                 "none": sorted(r for r, s in scored.items() if s == 0)}
        if fw == "csf":
            by_fn = {}
            for prefix, name in CSF_FUNCTIONS.items():
                vals = [s for r, s in scored.items() if r.startswith(prefix + ".")]
                by_fn[f"{prefix} {name}"] = round(100 * sum(vals) / len(vals), 1) if vals else None
            entry["by_function"] = by_fn
        coverage[fw] = entry

    gaps = []
    for c in CONTROLS:
        st = status[c["key"]]
        if st not in ("no", "partial"):
            continue
        answered = c["key"] in answers
        sev = c["priority"] if st == "no" else _lower(c["priority"])
        title = (f"{c['title']}: not in place" if st == "no" and answered else
                 f"{c['title']}: partly in place" if st == "partial" else f"{c['title']}: not assessed")
        refs = (["CSF " + ", ".join(c["csf"])] if c["csf"] else []) + \
               (["ISO " + ", ".join(c["iso"])] if c["iso"] else []) + \
               (["SOC 2 " + ", ".join(c["soc2"])] if c["soc2"] else []) + \
               (["NIS2 " + ", ".join(c["nis2"])] if c["nis2"] else [])
        note = answers.get(c["key"], {}).get("note", "")
        detail = c["question"] + (f" Answer note: {note}" if note else "") + \
            ("" if answered else " No answer given, counted as a gap.")
        gaps.append({"id": "GAP-" + c["code"][4:].zfill(3), "severity": sev, "title": title, "detail": detail,
                     "fix": c["fix"], "location": c["key"], "control": c["code"], "status": st,
                     "answered": answered, "mappings": "; ".join(refs)})
    gaps.sort(key=lambda g: (-SEVERITY_ORDER.index(g["severity"]), g["status"] != "no", g["control"]))
    totals = {k: sum(1 for a in answers.values() if a["answer"] == k) for k in ("yes", "partial", "no", "na")}
    totals["unanswered"] = sum(1 for c in CONTROLS if c["key"] not in answers)
    return {"disclaimer": DISCLAIMER, "controls": len(CONTROLS), "answers": totals,
            "coverage": coverage, "findings": gaps}


def render_text(result: Dict[str, Any]) -> str:
    t = result["answers"]
    L = ["# Control gap assessment", "",
         f"{result['controls']} controls: {t['yes']} yes, {t['partial']} partial, {t['no']} no, {t['na']} n/a "
         f"({t['unanswered']} unanswered).", "",
         "| Framework | Items mapped | Coverage | Full | Partial | None |", "|---|---|---|---|---|---|"]
    for fw, _ in FRAMEWORKS:
        c = result["coverage"][fw]
        pct = "n/a" if c["coverage_pct"] is None else f"{c['coverage_pct']}%"
        L.append(f"| {c['framework']} | {c['items_mapped']} | {pct} | {len(c['full'])} | {len(c['partial'])} | {len(c['none'])} |")
    L += ["", "NIST CSF 2.0 by function:", ""]
    for fn, pct in result["coverage"]["csf"]["by_function"].items():
        L.append(f"- {fn}: {'not mapped' if pct is None else str(pct) + '%'}")
    L += ["", f"## Gaps, highest priority first ({len(result['findings'])})", ""]
    if not result["findings"]:
        L.append("No gaps in the assessed controls.")
    for g in result["findings"]:
        L.append(f"- [{g['severity'].upper()}] {g['id']} {g['title']} ({g['mappings']})")
        L.append(f"  {g['detail']}")
        L.append(f"  Fix: {g['fix']}")
    L += ["", f"Note: {result['disclaimer']}"]
    return "\n".join(L) + "\n"


def render_list() -> str:
    L = ["| Code | Key | Control | Priority | NIST CSF 2.0 | ISO 27001:2022 | SOC 2 | NIS2 |",
         "|---|---|---|---|---|---|---|---|"]
    for c in CONTROLS:
        L.append(f"| {c['code']} | {c['key']} | {c['title']} | {c['priority']} | {', '.join(c['csf'])} | "
                 f"{', '.join(c['iso']) or '-'} | {', '.join(c['soc2']) or '-'} | {', '.join(c['nis2']) or '-'} |")
    L += ["", f"Note: {DISCLAIMER}"]
    return "\n".join(L) + "\n"


def render_template() -> str:
    L = ["# Answer each control: yes, partial, no or na. Text after the answer is kept as a note.",
         "# Example:  mfa: partial  admins only, not all staff", ""]
    for c in CONTROLS:
        L += [f"# {c['code']} {c['title']}: {c['question']}", f"{c['key']}: ?", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Map security control answers to NIST CSF 2.0, ISO 27001:2022, SOC 2 and NIS2 coverage.")
    ap.add_argument("file", nargs="?", help="answers file (text, CSV or JSON); '-' for stdin")
    ap.add_argument("--template", action="store_true", help="print a blank answers file and exit")
    ap.add_argument("--list", action="store_true", help="print the control mapping table and exit")
    ap.add_argument("--skip-unanswered", action="store_true",
                    help="leave unanswered controls out of coverage instead of counting them as gaps")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any gap is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    if args.template:
        print(render_template())
        return 0
    if args.list:
        print(render_list())
        return 0
    if not args.file:
        print("error: give an answers file (or --template / --list)", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8-sig").read()
        answers, warnings = parse_answers(text)
    except (OSError, ValueError, csv.Error) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not answers:
        print("error: no answers found (fill in the --template)", file=sys.stderr)
        return 2
    result = assess(answers, include_unanswered=not args.skip_unanswered)
    result["warnings"] = warnings
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        sys.stdout.write(render_text(result))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(g["severity"]) >= threshold for g in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
