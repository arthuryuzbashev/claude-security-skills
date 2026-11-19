"""Shared test helpers: load a skill script by path and run it as a CLI."""
from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"


def skill_path(skill: str, *parts: str) -> Path:
    return SKILLS.joinpath(skill, *parts)


def load_script(skill: str, script: str):
    """Import skills/<skill>/scripts/<script>.py as a module."""
    path = skill_path(skill, "scripts", f"{script}.py")
    name = f"secskills_{skill.replace('-', '_')}_{script}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def call_main(module, argv, stdin: str = ""):
    """Run module.main(argv) in-process. Returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = module.main(argv)
            except SystemExit as exc:  # argparse exits on --help / bad args
                code = exc.code
    finally:
        sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


def run_cli(skill: str, script: str, *args: str, stdin: str = ""):
    """Run the script as a real subprocess. Returns CompletedProcess."""
    path = skill_path(skill, "scripts", f"{script}.py")
    return subprocess.run([sys.executable, str(path), *args], input=stdin,
                          capture_output=True, text=True, timeout=60)
