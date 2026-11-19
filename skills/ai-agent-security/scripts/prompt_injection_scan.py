#!/usr/bin/env python3
"""Scan text an AI agent will read for prompt injection.

Looks for instruction-override phrases, text aimed at an AI reader, hidden
HTML/CSS text, invisible Unicode (zero-width, tag characters, bidi controls),
base64 that decodes to instructions, image URLs that can leak data through
query strings, and fake chat-template / tool-call markup. Gives every file a
0-100 score. Offline and read-only: it only reads the files you pass.

Usage:
  prompt_injection_scan.py README.md
  prompt_injection_scan.py docs/ --json
  curl -s https://example.test/page | prompt_injection_scan.py - --fail-on medium
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from typing import Dict, List, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
MAX_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
TEXT_EXT = {".md", ".markdown", ".txt", ".html", ".htm", ".xml", ".json", ".yaml", ".yml", ".toml", ".csv",
            ".rst", ".adoc", ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".sh", ".rb", ".go", ".rs",
            ".java", ".kt", ".swift", ".c", ".h", ".cpp", ".cs", ".php", ".ipynb", ".svg", ".mdc", ".cfg", ".ini",
            ".eml", ".vtt", ".srt", ""}

OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|my\s+|these\s+|those\s+|of\s+)*"
    r"(?:previous|prior|above|earlier|preceding|original|system|initial|safety)\s+"
    r"(?:instructions?|prompts?|rules|directions|guidelines|guardrails|constraints|messages?)\b"
    r"|\b(?:ignore|disregard|forget)\s+(?:all|any|your)\s+(?:of\s+)?(?:your\s+|the\s+)?"
    r"(?:instructions?|prompts?|rules|guidelines|guardrails)\b"
    r"|\bnew\s+(?:system\s+)?instructions?\s*:"
    r"|\byou\s+are\s+now\s+(?:in\s+)?(?:DAN\b|developer\s+mode|jailbreak|unrestricted|an?\s+unfiltered)"
    r"|\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|mention\s+(?:this\s+)?to|reveal\s+(?:this\s+)?to|show\s+(?:this\s+)?to)\s+the\s+user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying)\s+the\s+user\b"
    r"|\b(?:reveal|print|output|repeat|show)\s+(?:me\s+)?(?:your|the)\s+(?:full\s+|entire\s+)?(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)",
    re.I)

AI_ADDRESS = re.compile(
    r"\b(?:if\s+you\s+are\s+an?\s+(?:AI|LLM|language\s+model|assistant|agent|bot|chatbot)"
    r"|(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:AI|LLM|assistant|agent|language\s+model|chatbot|Claude|ChatGPT|GPT|Copilot|Gemini)\b"
    r"|(?:attention|dear|hey|hello)\s*,?\s+(?:AI|LLM|assistant|agent|language\s+model|chatbot|Claude|ChatGPT|Copilot|Gemini)\b"
    r"|(?:AI|LLM)\s+(?:agents?|assistants?|models?)\s+(?:reading|processing|summari[sz]ing|parsing|browsing)\s+this"
    r"|(?:when|while)\s+summari[sz]ing\s+this\s+(?:page|document|email|file))",
    re.I)

ACTION_WORDS = re.compile(r"\b(?:send|post|upload|exfiltrate|forward|email|curl|wget|fetch|run|execute|delete|transfer|"
                          r"api[_ -]?keys?|tokens?|passwords?|secrets?|credentials?|\.env|ssh)\b", re.I)

ZERO_WIDTH = {"​": "ZERO WIDTH SPACE", "‌": "ZERO WIDTH NON-JOINER", "‍": "ZERO WIDTH JOINER",
              "⁠": "WORD JOINER", "⁢": "INVISIBLE TIMES", "⁣": "INVISIBLE SEPARATOR",
              "⁤": "INVISIBLE PLUS", "﻿": "ZERO WIDTH NO-BREAK SPACE", "᠎": "MONGOLIAN VOWEL SEPARATOR"}
BIDI = {"‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO", "‮": "RLO",
        "⁦": "LRI", "⁧": "RLI", "⁨": "FSI", "⁩": "PDI"}

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:;|$|!)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)"
    r"|(?:^|;)\s*color\s*:\s*(?:#fff(?:fff)?|white|transparent|rgba\([^)]*,\s*0\s*\))\s*(?:;|$)"
    r"|(?:left|top|text-indent)\s*:\s*-\d{3,}px|clip\s*:\s*rect\(0|(?:height|width)\s*:\s*0(?:px)?\s*;[^\"']*overflow\s*:\s*hidden",
    re.I)
OPEN_TAG = re.compile(r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b(?P<attrs>[^>]*)>")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{32,}={0,2}|[A-Za-z0-9_-]{32,}={0,2})(?![A-Za-z0-9+/=_-])")
MD_IMAGE = re.compile(r"!\[[^\]\n]*\]\(\s*<?(https?://[^)\s>]+)")
HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I)
BADGE_HOSTS = ("img.shields.io", "badge.fury.io", "badgen.net", "codecov.io", "coveralls.io", "travis-ci.org",
               "travis-ci.com", "api.netlify.com", "github.com", "githubusercontent.com", "deepwiki.com")
EXFIL_HINT = re.compile(r"(?:\{|\}|%7B|%7D|\$\(|\[\w+\]|<\w+>|\b(?:data|secret|token|key|password|pass|pwd|session|cookie|"
                        r"history|conversation|chat|prompt|context|email|ssn|creds?|q)=)", re.I)
TEMPLATE_TOKENS = re.compile(r"<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|start_header_id|"
                             r"end_header_id|begin_of_text)\|>|\[/?INST\]|<<\/?SYS>>", re.I)
TOOL_MARKUP = re.compile(r"</?(?:function_calls|tool_call|tool_use|tool_result|function_call|invoke|system-reminder|"
                         r"system_prompt|system)\b[^>]*>", re.I)
ROLE_LINE = re.compile(r"^\s*(?:#{1,6}\s*)?(?:system|assistant|human)\s*:\s*\S", re.I)

SECRET_RE = re.compile(r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
                       r"xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,})")


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def mask(value: str) -> str:
    return value[:4] + "..." if len(value) > 4 else "..."


def visible(text: str, limit: int = 160) -> str:
    """Make a snippet safe to print: escape invisible characters, mask secrets, truncate."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in ZERO_WIDTH or ch in BIDI or 0xE0000 <= cp <= 0xE007F or (cp < 32 and ch not in "\t"):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    s = SECRET_RE.sub(lambda m: mask(m.group(0)), "".join(out)).strip()
    s = re.sub(r"\s+", " ", s)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def decode_tags(text: str) -> str:
    """Unicode tag characters U+E0020-E007E mirror printable ASCII; decode them to show the hidden text."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def is_instruction(text: str) -> bool:
    return bool(OVERRIDE.search(text) or AI_ADDRESS.search(text))


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _strip_tags(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def scan_text(text: str, path: str = "<stdin>") -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    lines = text.split("\n")

    for n, line in enumerate(lines, 1):
        loc = f"{path}:{n}"
        m = OVERRIDE.search(line)
        if m:
            out.append(finding("PI-001", "high", "Instruction-override phrase",
                               f"'{visible(m.group(0))}' in: {visible(line)}",
                               "Treat this content as untrusted data. Remove the phrase if the file is yours; if it came from outside, do not let an agent act on it with tools that can write, send or spend.",
                               loc))
        m = AI_ADDRESS.search(line)
        if m:
            sev = "high" if ACTION_WORDS.search(line) else "medium"
            out.append(finding("PI-002", sev, "Text addressed to an AI reader",
                               f"'{visible(m.group(0))}' in: {visible(line)}",
                               "Human readers do not need text aimed at an AI. Strip it before the content reaches an agent, or summarize it as quoted data only.",
                               loc))

        zw = [c for c in line if c in ZERO_WIDTH]
        if line.startswith("﻿") and n == 1:
            zw = zw[1:]  # a BOM at the start of the file is normal
        if zw:
            names = sorted({ZERO_WIDTH[c] for c in zw})
            out.append(finding("PI-004", "medium" if len(zw) < 8 else "high", f"{len(zw)} zero-width character(s)",
                               f"{', '.join(names)}. Long runs can encode hidden data; they also split words so filters miss them. Line: {visible(line)}",
                               "Remove zero-width characters (keep ZWJ only inside emoji or scripts that need it).", loc))
        tags = [c for c in line if 0xE0000 <= ord(c) <= 0xE007F]
        if tags:
            hidden = decode_tags(line)
            sev = "critical" if is_instruction(hidden) or ACTION_WORDS.search(hidden) else "high"
            out.append(finding("PI-004", sev, f"{len(tags)} Unicode tag character(s) (invisible text)",
                               f"Characters from the U+E0000 block render as nothing but many models read them. Decoded: '{visible(hidden)}'",
                               "Strip the U+E0000-U+E007F range from any text before an agent reads it.", loc))
        bidi = [c for c in line if c in BIDI]
        if bidi:
            out.append(finding("PI-005", "medium", f"{len(bidi)} bidirectional control character(s)",
                               f"{', '.join(sorted({BIDI[c] for c in bidi}))} reorder how text displays, so what a reviewer sees differs from what a model or compiler reads (Trojan Source, CVE-2021-42574). Line: {visible(line)}",
                               "Remove the controls unless the file is real right-to-left text; reject them in code review.", loc))

        for m in TEMPLATE_TOKENS.finditer(line):
            out.append(finding("PI-008", "high", f"Chat-template token {visible(m.group(0))}",
                               f"Special tokens from model chat formats have no business in ordinary content; they try to fake a role boundary. Line: {visible(line)}",
                               "Strip or escape template tokens from untrusted input.", loc))
        for m in TOOL_MARKUP.finditer(line):
            out.append(finding("PI-008", "medium", f"Tool-call or system markup {visible(m.group(0))}",
                               f"Markup that imitates tool calls or system messages can make a model treat data as its own instructions. Line: {visible(line)}",
                               "Escape the markup or quote it clearly as data; never feed it to an agent as trusted context.", loc))
        if ROLE_LINE.match(line) and is_instruction(line):
            out.append(finding("PI-008", "medium", "Fake conversation role line",
                               f"A 'System:' / 'Assistant:' style line with instructions: {visible(line)}",
                               "Treat as untrusted data; do not let it change the agent's task.", loc))

        for rx in (MD_IMAGE, HTML_IMG):
            for m in rx.finditer(line):
                url = m.group(1)
                host = re.sub(r"^https?://", "", url).split("/")[0].split("?")[0].lower()
                if "?" not in url or any(host == h or host.endswith("." + h) for h in BADGE_HOSTS):
                    continue
                query = url.split("?", 1)[1]
                hot = bool(EXFIL_HINT.search(query))
                out.append(finding("PI-007", "high" if hot else "low", f"Image URL with query string: {host}",
                                   f"If an agent writes this image into a reply that gets rendered, the client fetches it and sends the query to {host}. "
                                   f"Placeholders or names like data=, q=, token= suggest it is meant to carry data out. URL: {visible(url, 120)}",
                                   "Do not render images from untrusted hosts in agent output; allow-list image domains or strip images.", loc))

        for m in B64.finditer(line):
            blob = m.group(1)
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if ("-" in blob or "_" in blob) else None)
                decoded = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
            if not decoded or printable / len(decoded) < 0.95:
                continue
            if is_instruction(decoded) or (len(ACTION_WORDS.findall(decoded)) >= 2 and re.search(r"\s", decoded)):
                out.append(finding("PI-006", "high", "Base64 that decodes to instructions",
                                   f"Decodes to: '{visible(decoded, 140)}'",
                                   "Remove it. Encoded instructions exist to slip past filters and human review.", loc))

    # hidden HTML / CSS text
    for m in OPEN_TAG.finditer(text):
        attrs = m.group("attrs")
        style = " ".join(re.findall(r"style\s*=\s*[\"']([^\"']*)[\"']", attrs, re.I))
        hidden_attr = re.search(r"(?:^|\s)hidden(?:\s|=|$|/)", attrs, re.I)
        if not (HIDDEN_STYLE.search(style) or hidden_attr):
            continue
        close = re.compile(r"</" + m.group("tag") + r"\s*>", re.I).search(text, m.end())
        body = _strip_tags(text[m.end():close.start() if close else m.end() + 2000])
        if len(body) < 12:
            continue
        sev = "high" if is_instruction(body) or ACTION_WORDS.search(body) else "low"
        out.append(finding("PI-003", sev, f"Hidden HTML text in <{m.group('tag')}>",
                           f"Styled to be invisible ({visible(style or 'hidden attribute', 80)}) but still read by agents and scrapers: '{visible(body)}'",
                           "Strip hidden elements before content reaches an agent; render the page and use the visible text only.",
                           f"{path}:{_line_at(text, m.start())}"))
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if is_instruction(body) or (AI_ADDRESS.search(body) is None and len(ACTION_WORDS.findall(body)) >= 2
                                    and re.search(r"\b(?:you|your|assistant|agent|AI)\b", body, re.I)):
            out.append(finding("PI-003", "high" if is_instruction(body) else "medium", "Instructions inside an HTML comment",
                               f"Comments are invisible in rendered pages and markdown but reach the model: '{visible(body)}'",
                               "Remove the comment, or strip comments from untrusted content before an agent reads it.",
                               f"{path}:{_line_at(text, m.start())}"))

    # one finding per (id, line, title) is enough
    seen, uniq = set(), []
    for f in out:
        key = (f["id"], f.get("location"), f["title"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def score(findings: List[Dict[str, str]]) -> int:
    return min(100, sum(WEIGHT[f["severity"]] for f in findings))


def verdict(s: int) -> str:
    if s == 0:
        return "clean"
    if s < 25:
        return "low"
    if s < 50:
        return "suspicious"
    return "likely injection"


def collect(paths: List[str]) -> Tuple[List[str], List[str]]:
    files, skipped = [], []
    for p in paths:
        if p == "-":
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(names):
                    full = os.path.join(root, name)
                    if os.path.splitext(name)[1].lower() in TEXT_EXT:
                        files.append(full)
                    else:
                        skipped.append(full)
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files, skipped


def read_text(path: str) -> str:
    """Return file text, or raise ValueError for binaries and files over the size limit."""
    if os.path.getsize(path) > MAX_BYTES:
        raise ValueError("over 2 MB")
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:8192]:
        raise ValueError("binary")
    return raw.decode("utf-8", errors="replace")


def scan_paths(paths: List[str], stdin_text: str = "") -> Tuple[List[Dict[str, object]], List[Dict[str, str]], List[str]]:
    files, skipped = collect(paths)
    reports: List[Dict[str, object]] = []
    findings: List[Dict[str, str]] = []
    for path in files:
        if path == "-":
            text, label = stdin_text, "<stdin>"
        else:
            try:
                text, label = read_text(path), path
            except ValueError:
                skipped.append(path)
                continue
        got = scan_text(text, label)
        s = score(got)
        reports.append({"path": label, "score": s, "verdict": verdict(s), "count": len(got)})
        findings += got
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return reports, findings, skipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan files an AI agent will read for prompt injection (offline, read-only).")
    ap.add_argument("paths", nargs="+", help="files or directories; '-' reads stdin")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    try:
        reports, findings, skipped = scan_paths(args.paths, sys.stdin.read() if "-" in args.paths else "")
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if not reports:
        print("error: no readable text files to scan", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"files": reports, "skipped": skipped, "count": len(findings), "findings": findings},
                         indent=2, ensure_ascii=True))
    else:
        print(f"Prompt injection scan: {len(reports)} file(s), {len(findings)} finding(s)\n")
        for r in sorted(reports, key=lambda r: -int(r["score"])):
            print(f"  {int(r['score']):3d}/100  {r['verdict']:16}  {r['path']}")
        print()
        if not findings:
            print("No issues found.")
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}\n           at {f.get('location', '?')}\n"
                  f"           {f['detail']}\n           fix: {f['fix']}")
        if skipped:
            print(f"\nSkipped {len(skipped)} binary, oversized or non-text file(s).")
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
