#!/usr/bin/env bash
# Fuzz every Fuzz function in the module for the given time each (default 60s). One fuzz target
# per `go test` run is a limit of the toolchain, so this finds them and runs them in turn.
set -euo pipefail
cd "$(dirname "$0")/.."
time="${1:-60s}"
fail=0
while IFS= read -r line; do
  file="${line%%:*}"
  name="$(sed -E 's/^[0-9]+:func (Fuzz[A-Za-z0-9_]*).*/\1/' <<<"${line#*:}")"
  dir="$(dirname "$file")"
  echo "== $dir $name for $time"
  # The module of the package: api/ and sdk/ are their own modules.
  mod="."
  case "$dir" in api*) mod=api ;; sdk*) mod=sdk ;; esac
  rel="./${dir#"$mod"/}"
  [ "$mod" = "." ] && rel="./$dir"
  [ "$dir" = "$mod" ] && rel="."
  (cd "$mod" && go test -run '^$' -fuzz "^${name}\$" -fuzztime "$time" "$rel") || fail=1
done < <(grep -rn --include='*_test.go' '^func Fuzz' . | sed -E 's#^\./##')
exit "$fail"
