#!/usr/bin/env python3
"""Check every skill against docs/SKILL_STANDARD.md.

Usage:
  python3 tools/validate.py            # all skills
  python3 tools/validate.py web-appsec # one skill
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
REQUIRED_SECTIONS = ["## When to use", "## Ground rules", "## Workflow", "## Tools", "## Output", "## References"]
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}  # empty set on 3.9: check skipped
HAS_STDLIB_LIST = hasattr(sys, "stdlib_module_names")


def frontmatter(text: str):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    data = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")
    return data


def third_party_imports(path: Path):
    siblings = {p.stem for p in path.parent.glob("*.py")}
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bad = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for n in names:
            top = n.split(".")[0]
            if HAS_STDLIB_LIST and top not in STDLIB and top not in siblings:
                bad.add(top)
    return bad


def check_skill(skill: Path):
    errors, warnings = [], []
    name = skill.name
    if not NAME_RE.match(name):
        errors.append(f"folder name '{name}' must be lowercase letters, digits and hyphens")
    md = skill / "SKILL.md"
    if not md.exists():
        return [f"{name}: SKILL.md missing"], []
    text = md.read_text(encoding="utf-8")
    fm = frontmatter(text)
    if fm is None:
        errors.append("SKILL.md has no YAML frontmatter")
        fm = {}
    if fm.get("name") != name:
        errors.append(f"frontmatter name '{fm.get('name')}' must equal folder name '{name}'")
    desc = fm.get("description", "")
    if not desc:
        errors.append("frontmatter description missing")
    elif len(desc) > 1024:
        errors.append(f"description is {len(desc)} chars, max 1024")
    elif len(desc) < 80:
        warnings.append("description is short; name concrete triggers so Claude picks the skill")
    for section in REQUIRED_SECTIONS:
        if section not in text:
            errors.append(f"SKILL.md missing section '{section}'")
    lines = text.count("\n")
    if lines > 300:
        warnings.append(f"SKILL.md is {lines} lines; move detail into references/")

    for ref in re.findall(r"`((?:references|scripts|examples)/[^`\s]+)`", text):
        if not (skill / ref).exists():
            errors.append(f"SKILL.md points at {ref}, which does not exist")

    scripts = sorted((skill / "scripts").glob("*.py"))
    if not scripts:
        errors.append("no scripts/*.py")
    if len(list((skill / "references").glob("*.md"))) < 1:
        errors.append("no references/*.md")
    if not (skill / "examples").is_dir() or not any((skill / "examples").iterdir()):
        errors.append("examples/ missing or empty")
    test = ROOT / "tests" / f"test_{name.replace('-', '_')}.py"
    if not test.exists():
        errors.append(f"test file {test.relative_to(ROOT)} missing")

    for script in scripts:
        rel = script.relative_to(ROOT)
        src = script.read_text(encoding="utf-8")
        if not src.startswith("#!/usr/bin/env python3"):
            errors.append(f"{rel}: missing '#!/usr/bin/env python3' shebang")
        bad = third_party_imports(script)
        if bad:
            errors.append(f"{rel}: third-party imports {sorted(bad)} (stdlib only)")
        if "def main(" not in src:
            errors.append(f"{rel}: no main() function")
        r = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            errors.append(f"{rel}: --help exited {r.returncode}: {r.stderr.strip()[:200]}")
        if script.name not in text:
            warnings.append(f"{rel}: not mentioned in SKILL.md")
    return errors, warnings


def check_manifests(skill_names):
    errors = []
    mp = ROOT / ".claude-plugin" / "marketplace.json"
    pj = ROOT / ".claude-plugin" / "plugin.json"
    for f in (mp, pj):
        if not f.exists():
            errors.append(f"{f.relative_to(ROOT)} missing")
            continue
        try:
            json.loads(f.read_text())
        except json.JSONDecodeError as e:
            errors.append(f"{f.relative_to(ROOT)}: invalid JSON: {e}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    for n in skill_names:
        if f"skills/{n}" not in readme:
            errors.append(f"README.md does not list skills/{n}")
    return errors


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    targets = [SKILLS / a for a in argv] if argv else sorted(p for p in SKILLS.iterdir() if p.is_dir())
    total_err = 0
    for skill in targets:
        errors, warnings = check_skill(skill)
        status = "FAIL" if errors else "ok  "
        print(f"{status} {skill.name}")
        for e in errors:
            print(f"     error: {e}")
        for w in warnings:
            print(f"     warn:  {w}")
        total_err += len(errors)
    if not argv:
        manifest_errors = check_manifests([t.name for t in targets])
        for e in manifest_errors:
            print(f"FAIL repo: {e}")
        total_err += len(manifest_errors)
    print(f"\n{len(targets)} skill(s), {total_err} error(s)")
    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
