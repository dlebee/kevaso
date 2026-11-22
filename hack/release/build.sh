#!/usr/bin/env bash
# Builds the release binaries for one platform into DIR and checks each one carries VERSION.
#
#   hack/release/build.sh VERSION GOOS GOARCH DIR
#
# What each platform ships:
#   darwin/*   kvo, kvoadm
#   windows/*  kvo.exe, kvoadm.exe
#   linux/*    kvo, kvoadm, kevasod
#
# VERSION is the tag (v1.2.3 or v1.2.3-rc.1). It is stamped the way kevasod has always been
# stamped (internal/version), which `kevasod version` prints and `kvoadm upgrade` reads.
set -euo pipefail

VERSION="${1:?usage: $0 VERSION GOOS GOARCH DIR}"
GOOS_T="${2:?usage: $0 VERSION GOOS GOARCH DIR}"
GOARCH_T="${3:?usage: $0 VERSION GOOS GOARCH DIR}"
DIR="${4:?usage: $0 VERSION GOOS GOARCH DIR}"

if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
	echo "version $VERSION is not like v1.2.3 or v1.2.3-rc.1" >&2
	exit 1
fi

case "$GOOS_T" in
darwin) cmds=(kvo kvoadm) ;;
windows) cmds=(kvo kvoadm) ;;
linux) cmds=(kvo kvoadm kevasod) ;;
*) echo "no release for GOOS=$GOOS_T" >&2; exit 1 ;;
esac
ext=""
[ "$GOOS_T" = windows ] && ext=".exe"

VERSION_VAR="kevaso.com/core/internal/version.Version"
mkdir -p "$DIR"
for c in "${cmds[@]}"; do
	out="$DIR/$c$ext"
	echo "build $GOOS_T/$GOARCH_T $c $VERSION"
	# No -trimpath: with it Go leaves -ldflags out of the build info, and kvoadm upgrade reads
	# kevasod's version from there (internal/cli/kvoadm/upgrade.go binaryVersionOf).
	GOWORK=off CGO_ENABLED=0 GOOS="$GOOS_T" GOARCH="$GOARCH_T" \
		go build -ldflags "-s -w -X $VERSION_VAR=$VERSION" -o "$out" "./cmd/$c"
	# The tag and the stamped version must agree: read it back out of the binary.
	got="$(go version -m "$out" | sed -nE "s|.*-X $VERSION_VAR=([^ \"']+).*|\1|p" | head -1)"
	if [ "$got" != "$VERSION" ]; then
		echo "$out carries version '$got', want $VERSION" >&2
		exit 1
	fi
done
