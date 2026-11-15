#!/usr/bin/env bash
# Runs test/integration and the controllers' tests as several copies at once, each limited to two
# CPUs, under the race detector, so a test that waits on the wall clock or is wrong under load
# fails here and not on a merge. Every failing test's name and output are kept in $OUT.
set -uo pipefail
cd "$(dirname "$0")/.."
copies="${COPIES:-4}"; count="${COUNT:-3}"
out="${OUT:-$(mktemp -d)}"
go test -race -c -o "$out/integration.test" ./test/integration
fail=0
for i in $(seq "$copies"); do
  ( cd test/integration && GOMAXPROCS=2 "$out/integration.test" -test.count="$count" -test.timeout 30m >"$out/integration.$i.log" 2>&1 ) &
  ( GOMAXPROCS=2 go test -race -count="$count" ./internal/controllers/... >"$out/controllers.$i.log" 2>&1 ) &
done
wait
if grep -l -e '^--- FAIL' -e '^FAIL' "$out"/*.log >/dev/null 2>&1; then
  echo "failures under contention (logs in $out):"; grep -h '^--- FAIL' "$out"/*.log | sort | uniq -c; fail=1
fi
exit "$fail"
