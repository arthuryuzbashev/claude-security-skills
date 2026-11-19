#!/usr/bin/env python3
"""Map an attack surface from a hostname list: de-dup, classify risky names, spot dangling DNS.

Input is a plain list (one host per line), a crt.sh JSON export, or a CSV whose
first column is the host. Offline by default: it only classifies names. With
--records it also checks saved DNS answers; with --resolve it does live lookups.

Usage:
  surface_map.py hosts.txt --domain example.com
  surface_map.py crtsh.json --domain example.com --json
  surface_map.py hosts.txt --records dns_answers.txt      # offline dangling-CNAME check
  surface_map.py hosts.txt --domain example.com --resolve # live A/AAAA (+CNAME via dig)
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# category -> (severity, words matched against name tokens, why it matters)
CATEGORIES: Dict[str, Tuple[str, Tuple[str, ...], str]] = {
    "ci-cd": ("medium", ("jenkins", "gitlab", "ci", "cd", "drone", "teamcity", "bamboo", "argo", "argocd",
                          "build", "builds", "concourse", "nexus", "artifactory", "sonar", "sonarqube", "registry"),
              "build systems hold source, secrets and deploy keys"),
    "admin": ("medium", ("admin", "administrator", "manage", "manager", "cpanel", "whm", "plesk", "panel",
                         "backoffice", "console", "phpmyadmin", "adminer", "webmin"),
              "admin interfaces are high-value login targets"),
    "data": ("medium", ("db", "database", "mysql", "postgres", "pg", "mongo", "mongodb", "redis", "elastic",
                        "elasticsearch", "es", "kibana", "solr", "couch", "couchdb", "cassandra", "rabbitmq", "kafka"),
             "data stores should never face the internet"),
    "monitoring": ("low", ("grafana", "prometheus", "metrics", "zabbix", "nagios", "monitor",
                           "monitoring", "logs", "logging", "splunk", "sentry", "jaeger"),
                   "dashboards leak internals and often run with default logins"),
    "non-prod": ("low", ("dev", "develop", "development", "staging", "stage", "stg", "test", "testing", "qa",
                         "uat", "sandbox", "preprod", "demo", "beta", "canary", "tmp", "temp"),
                 "non-production apps get fewer patches and weaker auth"),
    "legacy": ("low", ("old", "legacy", "backup", "bak", "archive", "deprecated", "v1", "classic", "previous"),
               "forgotten hosts run unpatched software"),
    "remote-access": ("low", ("vpn", "remote", "rdp", "citrix", "vdi", "ssh", "bastion", "jump",
                              "owa", "exchange", "webmail", "sslvpn"),
                      "remote access endpoints are top targets for credential attacks"),
    "internal": ("info", ("internal", "intranet", "corp", "private", "local", "lan", "int"),
                 "names that say internal should usually not be in public DNS"),
    "auth": ("info", ("sso", "auth", "login", "idp", "adfs", "okta", "oauth", "id", "accounts"),
             "identity endpoints deserve MFA and rate limits"),
    "storage": ("info", ("s3", "bucket", "files", "uploads", "storage", "cdn", "assets", "media"),
                "storage hosts can expose listable buckets"),
    "api-docs": ("low", ("swagger", "openapi", "graphql", "graphiql", "redoc", "apidocs", "apidoc", "playground",
                         "postman"),
                 "API docs and GraphQL consoles list every endpoint and are often left open on non-prod APIs"),
}

# CNAME targets on services where an unclaimed name can often be registered by someone else.
# Based on the public can-i-take-over-xyz status list (checked 2026-11). Services listed there as
# not vulnerable (WP Engine, Zendesk, CloudFront, Fastly, Firebase, ELB) are left out, so a dangling
# CNAME to them is reported as SRF-022 instead. GitHub Pages, Heroku, Netlify and Vercel are edge
# cases (takeover depends on account and verification settings) and stay in.
TAKEOVER_SUFFIXES = (
    # AWS
    "s3.amazonaws.com", "s3-website", "elasticbeanstalk.com",
    # Azure
    "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net",
    "azureedge.net", "azure-api.net", "azurehdinsight.net", "azurecontainer.io", "database.windows.net",
    "azuredatalakestore.net", "search.windows.net", "azurecr.io", "redis.cache.windows.net",
    "servicebus.windows.net", "visualstudio.com",
    # hosting and site builders
    "herokuapp.com", "herokudns.com", "github.io", "netlify.app", "netlify.com", "vercel.app", "pages.dev",
    "ghost.io", "readthedocs.io", "surge.sh", "bitbucket.io", "pantheonsite.io", "wordpress.com",
    "s.strikinglydns.com", "launchrock.com", "worksites.net", "airee.ru", "animaapp.io", "hatenablog.com",
    "ngrok.io", "furyns.com",
    # help desks, docs and SaaS pages
    "helpscoutdocs.com", "helpjuice.com", "helprace.com", "readme.io", "trydiscourse.com", "agilecrm.com",
    "youtrack.cloud", "surveysparrow.com", "read.uberflip.com", "stats.uptimerobot.com",
)

HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")

Resolver = Callable[[str], Dict[str, object]]


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None) -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# ---------------------------------------------------------------- input

def extract_names(raw: str) -> List[str]:
    """Pull hostnames out of a crt.sh JSON export, CSV or plain list."""
    text = raw.strip()
    names: List[str] = []
    if text.startswith("[") or text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    for key in ("name_value", "common_name", "host", "hostname", "name", "domain"):
                        val = item.get(key)
                        if isinstance(val, str):
                            names.extend(val.split("\n"))
            return names
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first = re.split(r"[,\s;]", line)[0]
        names.append(first)
    return names


def normalize(names: List[str], domain: Optional[str] = None) -> Tuple[List[str], List[str], List[str]]:
    """Return (unique hosts, wildcard entries, rejected strings). Wildcards are stored without '*.'"""
    hosts, wilds, rejected = set(), set(), []
    domain = domain.lower().strip(".") if domain else None
    for raw in names:
        n = raw.strip().strip('"').lower().rstrip(".")
        n = re.sub(r"^[a-z]+://", "", n).split("/")[0].split(":")[0]
        if not n:
            continue
        if not HOST_RE.match(n):
            rejected.append(raw.strip())
            continue
        if domain and not (n == domain or n.endswith("." + domain) or n == "*." + domain):
            continue
        if n.startswith("*."):
            wilds.add(n[2:])
            hosts.add(n[2:])
        else:
            hosts.add(n)
    return sorted(hosts, key=lambda h: (h.split(".")[::-1])), sorted(wilds), rejected


def tokens(host: str, domain: Optional[str] = None) -> List[str]:
    """Words in the subdomain part. 'jenkins-old2.ci.example.com' -> ['jenkins', 'old', 'ci']"""
    sub = host
    if domain and host == domain.lower():
        sub = ""
    elif domain and host.endswith("." + domain.lower()):
        sub = host[: -len(domain) - 1]
    elif not domain:
        sub = ".".join(host.split(".")[:-2])
    out = []
    for part in re.split(r"[.\-_]", sub):
        part = re.sub(r"\d+$", "", part)
        if part:
            out.append(part)
    return out


def classify(host: str, domain: Optional[str] = None) -> List[str]:
    words = set(tokens(host, domain))
    return [cat for cat, (_, keys, _) in CATEGORIES.items() if words & set(keys)]


# ---------------------------------------------------------------- DNS evidence

def parse_records(raw: str) -> Dict[str, Dict[str, List[str]]]:
    """Parse dig/zone answer lines into {name: {"A": [...], "AAAA": [...], "CNAME": [...]}}."""
    table: Dict[str, Dict[str, List[str]]] = {}
    for line in raw.splitlines():
        line = line.split(";")[0].strip()
        m = re.match(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(A|AAAA|CNAME)\s+(\S+)", line, re.I)
        if not m:
            continue
        name, rtype, value = m.group(1).lower().rstrip("."), m.group(2).upper(), m.group(3).lower().rstrip(".")
        table.setdefault(name, {}).setdefault(rtype, []).append(value)
    return table


def records_resolver(table: Dict[str, Dict[str, List[str]]]) -> Resolver:
    def resolve(host: str) -> Dict[str, object]:
        chain, name, ips = [], host, []
        for _ in range(10):
            entry = table.get(name, {})
            if entry.get("CNAME"):
                name = entry["CNAME"][0]
                chain.append(name)
                continue
            ips = entry.get("A", []) + entry.get("AAAA", [])
            break
        return {"cname": chain, "ips": ips, "known": host in table}
    return resolve


def live_resolver(timeout: float = 4.0) -> Resolver:
    dig = shutil.which("dig")

    def resolve(host: str) -> Dict[str, object]:
        chain: List[str] = []
        if dig:
            try:
                proc = subprocess.run([dig, "+short", f"+time={max(1, int(timeout))}", "+tries=1", "CNAME", host],
                                      capture_output=True, text=True, timeout=timeout * 2)
                chain = [l.strip().rstrip(".").lower() for l in proc.stdout.splitlines() if l.strip()]
            except subprocess.TimeoutExpired:
                pass
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
        except (socket.gaierror, UnicodeError, OSError):
            ips = []
        return {"cname": chain, "ips": ips, "known": True}
    return resolve


def resolve_all(hosts: List[str], resolver: Resolver, workers: int = 16, timeout: float = 4.0) -> Dict[str, Dict[str, object]]:
    out: Dict[str, Dict[str, object]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(resolver, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            h = futures[fut]
            try:
                out[h] = fut.result(timeout=timeout * 4)
            except Exception:  # one slow or odd host must not kill the run
                out[h] = {"cname": [], "ips": [], "known": False}
    return out


def ip_flags(ips: List[str]) -> List[str]:
    flagged = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        # documentation ranges count as private in Python but are fake, not internal
        if addr.is_loopback or addr.is_link_local or (addr.is_private and not _is_doc_range(addr)):
            flagged.append(ip)
    return flagged


def _is_doc_range(addr) -> bool:
    docs = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    return any(addr in ipaddress.ip_network(n) for n in docs if ipaddress.ip_network(n).version == addr.version)


# ---------------------------------------------------------------- analysis

def analyze(hosts: List[str], wilds: List[str], domain: Optional[str] = None,
            dns: Optional[Dict[str, Dict[str, object]]] = None) -> Tuple[List[Dict[str, object]], List[Dict[str, str]]]:
    inventory: List[Dict[str, object]] = []
    findings: List[Dict[str, str]] = []
    for host in hosts:
        cats = classify(host, domain)
        entry: Dict[str, object] = {"host": host, "categories": cats, "wildcard": host in wilds}
        for cat in cats:
            sev, _, why = CATEGORIES[cat]
            findings.append(finding(f"SRF-{list(CATEGORIES).index(cat) + 1:03d}", sev,
                                    f"{cat} host exposed in public names",
                                    f"{host} matches the {cat} name pattern; {why}.",
                                    "Confirm it should be public. If not, move it behind VPN/SSO or remove the DNS name.", host))
        if dns is not None and host in dns:
            rec = dns[host]
            entry.update({"cname": rec.get("cname", []), "ips": rec.get("ips", [])})
            chain = rec.get("cname") or []
            ips = rec.get("ips") or []
            private = ip_flags(ips)  # type: ignore[arg-type]
            if private:
                findings.append(finding("SRF-020", "medium", "Public name points at a private address",
                                        f"{host} resolves to {', '.join(private)}. It leaks internal addressing and can help DNS rebinding.",
                                        "Serve internal names from split-horizon/internal DNS only.", host))
            if chain and not ips and rec.get("known", True):
                target = chain[-1]  # type: ignore[index]
                if any(target.endswith(s) or s in target for s in TAKEOVER_SUFFIXES):
                    findings.append(finding("SRF-021", "high", "Possible dangling CNAME (subdomain takeover candidate)",
                                            f"{host} -> {target}, which does not resolve and is on a service where names can be re-claimed.",
                                            "Verify by hand (provider's 'no such app/bucket' page), then delete the CNAME or re-claim the resource.", host))
                else:
                    findings.append(finding("SRF-022", "medium", "CNAME target does not resolve",
                                            f"{host} -> {target}, which returns no address.",
                                            "Remove the stale record or fix the target.", host))
            elif not chain and not ips and rec.get("known", True):
                findings.append(finding("SRF-023", "info", "Name does not resolve",
                                        f"{host} is in the list (often from old certificates) but has no address now.",
                                        "Fine if retired. Make sure no certificate or app still relies on it.", host))
        inventory.append(entry)
    for w in wilds:
        findings.append(finding("SRF-030", "info", "Wildcard certificate or name",
                                f"*.{w} hides which hosts exist; enumerate from DNS and inventory instead of CT logs.",
                                "Keep an internal list of hosts served under the wildcard.", f"*.{w}"))
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return inventory, findings


def summarize(inventory: List[Dict[str, object]]) -> Dict[str, int]:
    counts: Dict[str, int] = {"hosts": len(inventory)}
    for e in inventory:
        for c in e["categories"]:  # type: ignore[union-attr]
            counts[c] = counts.get(c, 0) + 1
    return counts


def render_text(summary, inventory, findings, rejected) -> str:
    lines = [f"Surface map: {summary['hosts']} unique host(s), {len(findings)} finding(s)"]
    cats = ", ".join(f"{k} {v}" for k, v in summary.items() if k != "hosts")
    if cats:
        lines.append(f"By category: {cats}")
    if rejected:
        lines.append(f"Skipped {len(rejected)} entries that are not hostnames")
    lines.append("")
    for e in inventory:
        extra = ""
        if e.get("cname"):
            extra += f"  cname {' -> '.join(e['cname'])}"
        if "ips" in e:
            extra += f"  ips {', '.join(e['ips']) or '(none)'}"
        tag = ",".join(e["categories"]) or "-"
        lines.append(f"  {e['host']:45} {tag}{extra}")
    lines.append("")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}: {f.get('location', '')}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Classify a hostname list and flag risky or dangling names.")
    ap.add_argument("input", help="hostname list, crt.sh JSON or CSV; '-' for stdin")
    ap.add_argument("--domain", help="keep only names under this domain (scope filter)")
    ap.add_argument("--records", help="saved DNS answers (dig/zone lines with A/AAAA/CNAME) for offline checks")
    ap.add_argument("--resolve", action="store_true", help="live DNS lookups (A/AAAA via the OS, CNAME via dig)")
    ap.add_argument("--max-hosts", type=int, default=2000, help="cap for --resolve (default 2000)")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8", errors="replace").read()
        rec_raw = open(args.records, encoding="utf-8", errors="replace").read() if args.records else None
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    hosts, wilds, rejected = normalize(extract_names(raw), args.domain)
    if not hosts:
        print("error: no hostnames found in input" + (f" under {args.domain}" if args.domain else ""), file=sys.stderr)
        return 2

    dns = None
    if rec_raw is not None:
        table = parse_records(rec_raw)
        dns = resolve_all(hosts, records_resolver(table), workers=1)
        dns = {h: r for h, r in dns.items() if r.get("known")}
    elif args.resolve:
        if len(hosts) > args.max_hosts:
            print(f"error: {len(hosts)} hosts is over --max-hosts {args.max_hosts}", file=sys.stderr)
            return 2
        socket.setdefaulttimeout(args.timeout)
        dns = resolve_all(hosts, live_resolver(args.timeout), timeout=args.timeout)

    inventory, findings = analyze(hosts, wilds, args.domain, dns)
    summary = summarize(inventory)
    if args.json:
        print(json.dumps({"summary": summary, "hosts": inventory, "rejected": rejected, "findings": findings}, indent=2))
    else:
        print(render_text(summary, inventory, findings, rejected))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
