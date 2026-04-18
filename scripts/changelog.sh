#!/usr/bin/env bash
set -euo pipefail

RANGE="${1:-HEAD}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for cat in feat fix perf security refactor docs test ci build chore other breaking; do
  : > "$tmp/$cat"
done

while IFS=$'\t' read -r sha subject; do
  [ -n "$subject" ] || continue

  breaking=0
  lower=$(printf '%s' "$subject" | tr '[:upper:]' '[:lower:]')
  case "$lower" in
    *"!:"*|*"breaking change"*) breaking=1 ;;
  esac

  prefix=$(printf '%s' "$subject" | sed -n 's/^\([a-zA-Z]\{1,12\}\)\(([^)]*)\)\{0,1\}!\{0,1\}:.*/\1/p' | tr '[:upper:]' '[:lower:]')
  rest=$(printf '%s' "$subject" | sed 's/^\([a-zA-Z]\{1,12\}\)\(([^)]*)\)\{0,1\}!\{0,1\}:[[:space:]]*//')

  cat=other
  case "$prefix" in
    feat|feature)       cat=feat ;;
    fix|bug|bugfix)     cat=fix ;;
    perf|performance)   cat=perf ;;
    sec|security)       cat=security ;;
    refactor|refac)     cat=refactor ;;
    docs|doc)           cat=docs ;;
    test|tests)         cat=test ;;
    ci)                 cat=ci ;;
    build|chore)        cat=chore ;;
  esac
  [ -z "$rest" ] && rest="$subject"

  printf -- '- %s (%s)\n' "$rest" "$sha" >> "$tmp/$cat"
  if [ "$breaking" = 1 ]; then
    printf -- '- %s (%s)\n' "$rest" "$sha" >> "$tmp/breaking"
  fi
done < <(git log --no-merges --pretty=format:'%h%x09%s' "$RANGE")

emit() {
  local file="$1" title="$2"
  if [ -s "$file" ]; then
    printf '### %s\n\n' "$title"
    cat "$file"
    printf '\n'
  fi
}

emit "$tmp/breaking" "Breaking changes"
emit "$tmp/feat"     "Features"
emit "$tmp/fix"      "Bug fixes"
emit "$tmp/perf"     "Performance"
emit "$tmp/security" "Security"
emit "$tmp/refactor" "Refactoring"
emit "$tmp/docs"     "Documentation"
emit "$tmp/test"     "Tests"
emit "$tmp/ci"       "CI"
emit "$tmp/chore"    "Build / chore"
emit "$tmp/other"    "Other"

has_any=0
for cat in breaking feat fix perf security refactor docs test ci chore other; do
  [ -s "$tmp/$cat" ] && has_any=1
done
[ "$has_any" = 0 ] && printf 'No notable changes.\n'
