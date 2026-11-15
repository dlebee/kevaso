#!/bin/sh
# Checks the long soak on the two machines (TestMetal2LongSoakCheck), from this Mac:
#
#   test/e2e/longsoak-check.sh ENV_FILE
#
# ENV_FILE sets the KEVASO_METAL_* variables of both machines (the same file the two-machine
# suite uses). It changes nothing on the machines: every silo running once and never restarted,
# the volume's checksum intact, no leaked rules, links, mounts, logical volumes or processes
# compared with the setup, the staging certificate still served and valid, the lease as it
# should be. Exit 0: all good. The output ends with what listens on each external IP.
set -e
[ -n "$1" ] || { echo "usage: $0 ENV_FILE" >&2; exit 2; }
. "$1"
cd "$(dirname "$0")/../.."
KEVASO_METAL_REUSE=1 exec go test -tags metal -run '^TestMetal2LongSoakCheck$' -count=1 -v -timeout 30m ./test/e2e/
