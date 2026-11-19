#!/usr/bin/env bash
# Install Aegis skills into Claude Code.
#
#   ./install.sh                     copy every skill to ~/.claude/skills (all projects)
#   ./install.sh --link              symlink instead, so `git pull` updates them
#   ./install.sh --project ./myapp   install into one project's .claude/skills
#   ./install.sh web-appsec vuln-triage   only these skills
#   ./install.sh --uninstall         remove Aegis skills from the target
#   ./install.sh --list              show available skills
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${HOME}/.claude/skills"
MODE="copy"
UNINSTALL=0
PICK=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --link) MODE="link" ;;
    --project) shift; TARGET="$(cd "${1:?--project needs a path}" && pwd)/.claude/skills" ;;
    --uninstall) UNINSTALL=1 ;;
    --list)
      for d in "$REPO"/skills/*/; do
        n="$(basename "$d")"
        desc="$(sed -n 's/^description: //p' "$d/SKILL.md" | head -1 | cut -c1-90)"
        printf "  %-22s %s...\n" "$n" "$desc"
      done
      exit 0 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) PICK+=("$1") ;;
  esac
  shift
done

if [[ ${#PICK[@]} -eq 0 ]]; then
  for d in "$REPO"/skills/*/; do PICK+=("$(basename "$d")"); done
fi

mkdir -p "$TARGET"
count=0
for name in "${PICK[@]}"; do
  src="$REPO/skills/$name"
  dst="$TARGET/$name"
  if [[ ! -f "$src/SKILL.md" ]]; then
    echo "skip: no skill named '$name' (try --list)" >&2
    continue
  fi
  if [[ $UNINSTALL -eq 1 ]]; then
    if [[ -L "$dst" || -f "$dst/SKILL.md" ]]; then rm -rf "$dst"; echo "removed  $name"; count=$((count+1)); fi
    continue
  fi
  if [[ -e "$dst" || -L "$dst" ]]; then
    if [[ ! -L "$dst" ]] && [[ ! -f "$dst/SKILL.md" ]]; then
      echo "skip: $dst exists and is not a skill, leaving it alone" >&2
      continue
    fi
    rm -rf "$dst"
  fi
  if [[ "$MODE" == "link" ]]; then ln -s "$src" "$dst"; else cp -R "$src" "$dst"; fi
  echo "installed $name"
  count=$((count+1))
done

if [[ $UNINSTALL -eq 1 ]]; then
  echo "Removed $count skill(s) from $TARGET"
else
  echo "Done: $count skill(s) in $TARGET ($MODE). Restart Claude Code, then ask e.g. \"audit the security headers of my staging site\"."
fi
