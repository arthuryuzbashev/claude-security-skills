#!/usr/bin/env python3
"""Lint Sigma detection rules (YAML or JSON) before they go into a SIEM.

Checks required fields (title, id as UUID, status, logsource, detection,
condition), valid status and level values, that the condition only names
selections that exist, ATT&CK tag format (attack.t1059.001), known value
modifiers, date format, falsepositives and duplicate ids across files.

Ships its own small YAML reader that covers what Sigma rules use (mappings,
lists, lists of mappings, quoted and block scalars, inline [a, b] lists).

Usage:
  sigma_lint.py rules/
  sigma_lint.py rule.yml other.yml --json
  sigma_lint.py rules/ --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TACTIC_TAGS = {"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
               "privilege-escalation", "defense-evasion", "credential-access", "discovery",
               "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"}
MODIFIERS = {"contains", "startswith", "endswith", "all", "base64", "base64offset", "re", "i", "m", "s",
             "windash", "cidr", "wide", "utf16le", "utf16be", "utf16", "exists", "expand", "fieldref",
             "gt", "gte", "lt", "lte", "cased", "neq"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
CONDITION_WORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}


class YamlError(ValueError):
    pass


# ---------------------------------------------------------------- tiny YAML reader

def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    t = text.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if len(t) >= 2 and t[0] == t[-1] == "'":
        return t[1:-1].replace("''", "'")
    if len(t) >= 2 and t[0] == t[-1] == '"':
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        return [_scalar(p) for p in _split_flow(t[1:-1])] if t[1:-1].strip() else []
    if t.startswith("{") and t.endswith("}"):
        out = {}
        for p in _split_flow(t[1:-1]):
            k, _, v = p.partition(":")
            out[str(_scalar(k))] = _scalar(v)
        return out
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def _split_flow(s: str) -> List[str]:
    parts, buf, depth, quote = [], [], 0, None
    for c in s:
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            continue
        if c in "'\"":
            quote = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(c)
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


def _split_key(content: str):
    """Return (key, rest) if the line is `key: value` / `key:`, else None."""
    quote = None
    for i, c in enumerate(content):
        if quote:
            if c == quote:
                quote = None
            continue
        if c in "'\"" and i == 0:
            quote = c
        elif c == ":" and (i + 1 == len(content) or content[i + 1] in " \t"):
            key = content[:i].strip()
            if key[:1] in "'\"" and key[-1:] == key[:1]:
                key = key[1:-1]
            return key, content[i + 1:].strip()
    return None


class _Lines:
    def __init__(self, text: str):
        self.items = []  # (indent, content, raw, lineno)
        for no, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[:len(raw) - len(raw.lstrip())]:
                raise YamlError(f"line {no}: tabs are not allowed for indentation")
            content = _strip_comment(raw)
            if not content.strip():
                self.items.append((None, "", raw, no))
                continue
            self.items.append((len(content) - len(content.lstrip()), content.strip(), raw, no))
        self.pos = 0

    def skip_blank(self):
        while self.pos < len(self.items) and self.items[self.pos][0] is None:
            self.pos += 1

    def peek(self):
        self.skip_blank()
        return self.items[self.pos] if self.pos < len(self.items) else None


def _parse_block(lines: _Lines, indent: int):
    first = lines.peek()
    if first is None:
        return None
    if first[1] == "-" or first[1].startswith("- "):
        return _parse_list(lines, first[0])
    return _parse_map(lines, first[0])


def _block_scalar(lines: _Lines, parent_indent: int, style: str) -> str:
    collected, block_indent = [], None
    while lines.pos < len(lines.items):
        ind, content, raw, _ = lines.items[lines.pos]
        if raw.strip() == "":
            collected.append("")
            lines.pos += 1
            continue
        raw_ind = len(raw) - len(raw.lstrip())
        if raw_ind <= parent_indent:
            break
        if block_indent is None:
            block_indent = raw_ind
        collected.append(raw[block_indent:])
        lines.pos += 1
    while collected and collected[-1] == "":
        collected.pop()
    if style.startswith(">"):
        return " ".join(c.strip() for c in collected if c.strip())
    return "\n".join(collected)


def _value_after_key(lines: _Lines, indent: int, rest: str):
    if rest in ("|", "|-", "|+", ">", ">-", ">+"):
        return _block_scalar(lines, indent, rest)
    if rest:
        return _scalar(rest)
    nxt = lines.peek()
    if nxt is None:
        return None
    if nxt[0] > indent or (nxt[0] == indent and (nxt[1] == "-" or nxt[1].startswith("- "))):
        return _parse_block(lines, nxt[0])
    return None


def _parse_map(lines: _Lines, indent: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    while True:
        item = lines.peek()
        if item is None or item[0] < indent:
            return out
        ind, content, _, no = item
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        if content == "-" or content.startswith("- "):
            return out  # a sibling list at the same indent ends this map (handled by caller)
        kv = _split_key(content)
        if kv is None:
            raise YamlError(f"line {no}: expected 'key: value', got '{content[:40]}'")
        key, rest = kv
        lines.pos += 1
        if key in out:
            raise YamlError(f"line {no}: duplicate key '{key}'")
        out[key] = _value_after_key(lines, indent, rest)


def _parse_list(lines: _Lines, indent: int) -> List[Any]:
    out: List[Any] = []
    while True:
        item = lines.peek()
        if item is None or item[0] < indent:
            return out
        ind, content, raw, no = item
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        if not (content == "-" or content.startswith("- ")):
            return out
        rest = content[1:].lstrip()
        if not rest:
            lines.pos += 1
            nxt = lines.peek()
            out.append(_parse_block(lines, nxt[0]) if nxt and nxt[0] > indent else None)
            continue
        kv = _split_key(rest) if not rest.startswith(("'", '"', "[", "{")) else None
        if kv is None and rest[:1] in "'\"":
            # a quoted key is still a mapping item: - 'a': b
            kv2 = _split_key(rest)
            kv = kv2 if kv2 and not _scalar_like(rest) else None
        if kv is None:
            lines.pos += 1
            out.append(_scalar(rest))
            continue
        # mapping inside a list item: rewrite this line as if the key started a block
        child_indent = indent + (len(content) - len(rest))
        lines.items[lines.pos] = (child_indent, rest, raw, no)
        out.append(_parse_map(lines, child_indent))


def _scalar_like(s: str) -> bool:
    s = s.strip()
    return len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]


def load_yaml_docs(text: str) -> List[Any]:
    """Parse a YAML stream (documents split by ---) into Python objects."""
    docs, chunk = [], []
    for line in text.splitlines():
        if line.strip() == "---" or line.startswith("--- "):
            if any(l.strip() and not l.strip().startswith("#") for l in chunk):
                docs.append("\n".join(chunk))
            chunk = []
        elif line.strip() == "...":
            continue
        else:
            chunk.append(line)
    if any(l.strip() and not l.strip().startswith("#") for l in chunk):
        docs.append("\n".join(chunk))
    out = []
    for d in docs:
        lines = _Lines(d)
        first = lines.peek()
        val = _parse_block(lines, first[0] if first else 0)
        rest = lines.peek()
        if rest is not None:
            raise YamlError(f"line {rest[3]}: could not parse '{rest[1][:40]}'")
        out.append(val)
    return out


def load_rules(path: str) -> List[Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith(".json") or text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    return load_yaml_docs(text)


# ---------------------------------------------------------------- lint

def finding(fid, severity, title, detail, fix, location=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def condition_identifiers(condition: str) -> Tuple[List[str], List[str]]:
    """Return (plain identifiers, 'x of pattern' patterns) used in a condition."""
    cond = condition.split("|", 1)[0]
    patterns = re.findall(r"\b(?:\d+|all|any)\s+of\s+([\w*]+)", cond)
    cleaned = re.sub(r"\b(?:\d+|all|any)\s+of\s+[\w*]+", " ", cond)
    names = [t for t in re.findall(r"[\w*]+", cleaned) if t.lower() not in CONDITION_WORDS]
    return names, patterns


def _pattern_re(p: str):
    return re.compile("^" + re.escape(p).replace(r"\*", ".*") + "$")


def lint_rule(rule: Any, where: str = "") -> List[Dict]:
    out = []
    loc = where or None
    if not isinstance(rule, dict):
        return [finding("SIG-000", "high", "Not a Sigma rule", "The document is not a mapping of fields.", "Start from a Sigma rule template.", loc)]
    if rule.get("action") in ("global", "reset", "repeat"):
        return [finding("SIG-099", "info", "Rule collection action document skipped",
                        f"action: {rule.get('action')} documents are merged into the following rules by Sigma tooling and are not linted alone.",
                        "Prefer one rule per file; collections are deprecated in Sigma 2.", loc)]
    title = rule.get("title")
    if not title:
        out.append(finding("SIG-001", "high", "title missing", "Every Sigma rule needs a title.", "Add `title:` with a short description of what is detected.", loc))
    elif len(str(title)) > 256:
        out.append(finding("SIG-004", "low", "title too long", f"{len(str(title))} characters; Sigma recommends a short title.", "Keep the title under 256 characters and move detail into description.", loc))
    rid = rule.get("id")
    if rid is None:
        out.append(finding("SIG-002", "medium", "id missing", "Without a stable id, rules cannot be tracked across versions or deduplicated.", "Add `id:` with a random UUID (python3 -c 'import uuid; print(uuid.uuid4())').", loc))
    elif not UUID_RE.match(str(rid)):
        out.append(finding("SIG-002", "medium", "id is not a UUID", f"id '{rid}' is not in UUID format.", "Use a random UUID version 4.", loc))
    status = rule.get("status")
    if status is None:
        out.append(finding("SIG-010", "medium", "status missing", "Consumers use status to decide whether to deploy the rule.", "Add `status:` (experimental, test or stable).", loc))
    elif str(status) not in STATUSES:
        out.append(finding("SIG-010", "medium", "invalid status", f"'{status}' is not one of {', '.join(sorted(STATUSES))}.", "Use a valid status value.", loc))
    level = rule.get("level")
    if level is None:
        out.append(finding("SIG-011", "low", "level missing", "Without a level the SIEM cannot prioritise alerts.", "Add `level:` (informational, low, medium, high, critical).", loc))
    elif str(level) not in LEVELS:
        out.append(finding("SIG-011", "medium", "invalid level", f"'{level}' is not one of {', '.join(sorted(LEVELS))}.", "Use a valid level value.", loc))
    if not rule.get("description"):
        out.append(finding("SIG-012", "info", "description missing", "Analysts triaging the alert need to know what it means.", "Add a one or two sentence `description:`.", loc))

    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        out.append(finding("SIG-060", "high", "logsource missing", "Sigma needs logsource to know which logs the rule applies to.", "Add `logsource:` with category/product/service.", loc))
    elif not any(k in ls for k in ("category", "product", "service")):
        out.append(finding("SIG-060", "high", "logsource has no category, product or service", f"logsource keys: {', '.join(ls) or 'none'}.", "Set at least one of category, product, service.", loc))

    det = rule.get("detection")
    if not isinstance(det, dict):
        out.append(finding("SIG-020", "high", "detection missing", "The rule has no detection block.", "Add `detection:` with selections and a condition.", loc))
    else:
        out += lint_detection(det, loc)

    tags = rule.get("tags") or []
    if not isinstance(tags, list):
        out.append(finding("SIG-030", "low", "tags is not a list", "tags must be a YAML list.", "Write tags as a list of strings.", loc))
        tags = []
    has_attack = False
    for t in tags:
        t = str(t)
        if t.lower().startswith("attack."):
            has_attack = True
            body = t[len("attack."):]
            ok = (re.fullmatch(r"t\d{4}(\.\d{3})?", body) or re.fullmatch(r"[gs]\d{4}", body) or body in TACTIC_TAGS)
            if not ok:
                hint = "lowercase, e.g. attack.t1059.001" if body.lower() != body else "use attack.tNNNN[.NNN], attack.gNNNN, attack.sNNNN or a tactic name like attack.execution"
                out.append(finding("SIG-030", "low", f"bad ATT&CK tag '{t}'", "Sigma ATT&CK tags are lowercase with dots.", hint, loc))
        elif not re.fullmatch(r"[a-z0-9_-]+\.[a-z0-9._-]+", t):
            out.append(finding("SIG-031", "low", f"tag '{t}' does not follow namespace.value", "Sigma tags look like attack.execution, cve.2021-44228, car.2016-04-005, detection.threat-hunting.", "Lowercase and use a namespace prefix.", loc))
    if not has_attack:
        out.append(finding("SIG-032", "info", "no ATT&CK tags", "Tags let you measure coverage per technique.", "Add attack.<tactic> and attack.tNNNN tags.", loc))

    fps = rule.get("falsepositives")
    if not fps:
        out.append(finding("SIG-040", "low", "falsepositives missing", "Triage is faster when known benign causes are listed.", "Add `falsepositives:` (use 'Unknown' if you truly have none).", loc))

    for key in ("date", "modified"):
        v = rule.get(key)
        if v is None:
            if key == "date":
                out.append(finding("SIG-050", "info", "date missing", "The creation date helps age and review rules.", "Add `date: YYYY-MM-DD`.", loc))
            continue
        v = str(v)
        if re.fullmatch(r"\d{4}/\d{2}/\d{2}", v):
            out.append(finding("SIG-050", "low", f"{key} uses the old YYYY/MM/DD format", f"{key}: {v}", "Use ISO 8601 YYYY-MM-DD.", loc))
        elif not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])", v):
            out.append(finding("SIG-050", "medium", f"{key} is not a valid date", f"{key}: {v}", "Use ISO 8601 YYYY-MM-DD.", loc))
    return out


def _iter_field_keys(selection):
    if isinstance(selection, dict):
        yield from selection.keys()
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                yield from item.keys()


def lint_detection(det: Dict, loc) -> List[Dict]:
    out = []
    cond = det.get("condition")
    selections = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
    if cond is None:
        out.append(finding("SIG-021", "high", "condition missing", "detection has no condition, so nothing ever matches.", "Add `condition:` e.g. `selection and not filter`.", loc))
        return out
    conds = cond if isinstance(cond, list) else [cond]
    if isinstance(cond, list):
        out.append(finding("SIG-026", "low", "condition is a list", "Lists of conditions are deprecated in Sigma 2.", "Combine them with `or` into one condition.", loc))
    if not selections:
        out.append(finding("SIG-022", "high", "no selections", "detection only has a condition.", "Add at least one named selection.", loc))
    used = set()
    for c in conds:
        c = str(c)
        if c.count("(") != c.count(")"):
            out.append(finding("SIG-023", "high", "unbalanced parentheses in condition", c, "Fix the parentheses.", loc))
        if "|" in c:
            out.append(finding("SIG-027", "low", "aggregation in condition", "Pipe aggregations (| count() ...) are deprecated in Sigma 2 and many backends ignore them.", "Use a Sigma correlation rule instead.", loc))
        names, patterns = condition_identifiers(c)
        for n in names:
            if n not in selections:
                out.append(finding("SIG-020", "high", f"condition uses undefined selection '{n}'", f"condition: {c}", f"Define `{n}` under detection or fix the name.", loc))
            used.add(n)
        for p in patterns:
            if p == "them":
                used.update(selections)
                continue
            rx = _pattern_re(p)
            hits = [s for s in selections if rx.match(s)]
            if not hits:
                out.append(finding("SIG-020", "high", f"condition pattern '{p}' matches no selection", f"condition: {c}", "Rename the selections or fix the pattern.", loc))
            used.update(hits)
    for s in selections:
        if s not in used:
            out.append(finding("SIG-024", "low", f"selection '{s}' is never used", "It is defined but the condition does not reference it.", "Use it in the condition or delete it.", loc))
    for name, sel in selections.items():
        if sel is None or sel == {} or sel == []:
            out.append(finding("SIG-025", "medium", f"selection '{name}' is empty", "An empty selection matches nothing or everything depending on the backend.", "Add field conditions or remove it.", loc))
        for key in _iter_field_keys(sel):
            parts = str(key).split("|")
            for mod in parts[1:]:
                if mod not in MODIFIERS:
                    out.append(finding("SIG-070", "medium", f"unknown modifier '{mod}' in '{key}'", f"Known: {', '.join(sorted(MODIFIERS))}.", "Fix the spelling (contains, startswith, endswith, re, all...).", loc))
            if "re" in parts[1:] and isinstance(sel, dict):
                vals = sel.get(key)
                for v in (vals if isinstance(vals, list) else [vals]):
                    try:
                        re.compile(str(v))
                    except re.error as err:
                        out.append(finding("SIG-071", "high", f"invalid regex in '{key}'", f"{v!r}: {err}", "Fix the regular expression.", loc))
    return out


def collect_files(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in sorted(names) if n.lower().endswith((".yml", ".yaml", ".json"))]
        else:
            files.append(p)
    return files


def lint_paths(paths: List[str]) -> Dict:
    results, seen_ids = [], {}
    for path in collect_files(paths):
        try:
            docs = load_rules(path)
        except (YamlError, json.JSONDecodeError, OSError, UnicodeDecodeError) as err:
            results.append({"file": path, "title": None, "findings": [finding("SIG-000", "high", "File could not be parsed", str(err), "Fix the YAML syntax (indentation, quotes, colons).", path)]})
            continue
        for i, rule in enumerate(docs):
            where = path if len(docs) == 1 else f"{path} (document {i + 1})"
            f = lint_rule(rule, where)
            rid = rule.get("id") if isinstance(rule, dict) else None
            if rid:
                if rid in seen_ids:
                    f.append(finding("SIG-003", "medium", "duplicate id", f"id {rid} is also used in {seen_ids[rid]}.", "Give every rule its own UUID.", where))
                else:
                    seen_ids[rid] = where
            f.sort(key=lambda x: (-SEVERITY_ORDER.index(x["severity"]), x["id"]))
            results.append({"file": where, "title": rule.get("title") if isinstance(rule, dict) else None, "findings": f})
    return {"rules": results, "summary": {s: sum(1 for r in results for f in r["findings"] if f["severity"] == s) for s in SEVERITY_ORDER}}


def render_text(result: Dict) -> str:
    out = []
    for r in result["rules"]:
        bad = [f for f in r["findings"] if f["severity"] != "info"]
        out.append(f"{'FAIL' if any(f['severity'] in ('high', 'critical') for f in r['findings']) else 'ok  '} {r['file']}"
                   + (f"  ({r['title']})" if r["title"] else ""))
        for f in r["findings"]:
            out.append(f"     [{f['severity'].upper():8}] {f['id']}  {f['title']}")
            if f["severity"] != "info":
                out.append(f"                {f['detail']}")
                out.append(f"                fix: {f['fix']}")
        if not bad and not r["findings"]:
            out.append("     clean")
    s = result["summary"]
    out.append("")
    out.append(f"{len(result['rules'])} rule(s): " + ", ".join(f"{s[k]} {k}" for k in reversed(SEVERITY_ORDER)))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lint Sigma rules (YAML or JSON).")
    ap.add_argument("paths", nargs="+", help="rule files or folders")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    files = collect_files(args.paths)
    missing = [p for p in files if not os.path.isfile(p)]
    if missing or not files:
        print(f"error: no rule files found{': ' + ', '.join(missing) if missing else ''}", file=sys.stderr)
        return 2
    result = lint_paths(args.paths)
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for r in result["rules"] for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
