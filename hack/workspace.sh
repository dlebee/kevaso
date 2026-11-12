#!/usr/bin/env bash
# Writes go.work in the folder that holds this repo, so core, its api and sdk modules, and any
# sibling provider repos (kevaso-provider-*) build against each other's local code.
# go.work is never committed; it only exists in your workspace folder.
set -euo pipefail
core="$(cd "$(dirname "$0")/.." && pwd)"
ws="$(dirname "$core")"
cd "$ws"
mods=("./$(basename "$core")" "./$(basename "$core")/api" "./$(basename "$core")/sdk")
for d in */; do
  d="${d%/}"
  [[ "$d" == "$(basename "$core")" ]] && continue
  [[ -f "$d/go.mod" ]] && mods+=("./$d")
done
go work init 2>/dev/null || true
go work use "${mods[@]}"
echo "wrote $ws/go.work:"; cat go.work
