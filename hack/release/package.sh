#!/usr/bin/env bash
# Packages what hack/release/build.sh left in BUILDROOT/<goos>-<goarch>/ into release archives in OUT,
# one archive per program:
#
#   hack/release/package.sh VERSION BUILDROOT OUT
#
#   kvo-VERSION-<goos>-<goarch>.zip / .tar.gz      kvo, LICENSE, NOTICE, README.md
#   kvoadm-VERSION-<goos>-<goarch>.zip / .tar.gz   kvoadm, LICENSE, NOTICE, README.md
#   kevasod-VERSION-linux-<goarch>.tar.gz          kevasod, LICENSE, NOTICE
#
# macOS and Windows get .zip, Linux .tar.gz. Each archive holds one top-level directory named like
# the archive. Binaries are packaged as they are, so sign them before this runs.
set -euo pipefail

VERSION="${1:?usage: $0 VERSION BUILDROOT OUT}"
ROOT="${2:?usage: $0 VERSION BUILDROOT OUT}"
OUT="${3:?usage: $0 VERSION BUILDROOT OUT}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

archive() { # archive KIND NAME — STAGE/NAME becomes OUT/NAME.zip or OUT/NAME.tar.gz
	if [ "$1" = zip ]; then
		if command -v ditto >/dev/null; then
			ditto -c -k --keepParent "$STAGE/$2" "$OUT/$2.zip"
		else
			(cd "$STAGE" && zip -qr "$OUT/$2.zip" "$2")
		fi
	else
		tar -C "$STAGE" -czf "$OUT/$2.tar.gz" "$2"
	fi
	echo "packaged $2"
}

found=0
for dir in "$ROOT"/*-*/; do
	[ -d "$dir" ] || continue
	plat="$(basename "$dir")"
	kind=zip
	[ "${plat%-*}" = linux ] && kind=tgz
	for f in "$dir"*; do
		prog="$(basename "$f" .exe)"
		case "$prog" in
		kvo | kvoadm) extra=(README.md) ;;
		kevasod) extra=() ;;
		*) continue ;;
		esac
		found=1
		name="$prog-$VERSION-$plat"
		mkdir -p "$STAGE/$name"
		cp -p "$f" "$STAGE/$name/"
		for x in LICENSE NOTICE ${extra[@]+"${extra[@]}"}; do cp "$REPO/$x" "$STAGE/$name/"; done
		archive "$kind" "$name"
	done
done
[ "$found" = 1 ] || { echo "nothing built in $ROOT" >&2; exit 1; }
