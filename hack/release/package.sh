#!/usr/bin/env bash
# Packages what hack/release/build.sh left in BUILDROOT/<goos>-<goarch>/ into release archives in OUT.
#
#   hack/release/package.sh VERSION BUILDROOT OUT
#
#   kevaso-cli-VERSION-<goos>-<goarch>.zip     darwin, windows: kvo (and kvoadm), LICENSE, NOTICE, README.md
#   kevaso-cli-VERSION-linux-<goarch>.tar.gz   linux: kvo, kvoadm, LICENSE, NOTICE, README.md
#   kevasod-VERSION-linux-<goarch>.tar.gz      linux: kevasod, LICENSE, NOTICE
#
# Each archive holds one top-level directory named like the archive. Binaries are packaged as they
# are, so on macOS sign them before this runs.
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
	found=1
	plat="$(basename "$dir")"
	goos="${plat%-*}"
	kind=zip
	[ "$goos" = linux ] && kind=tgz

	cli="kevaso-cli-$VERSION-$plat"
	mkdir -p "$STAGE/$cli"
	for b in kvo kvo.exe kvoadm kvoadm.exe; do
		[ -f "$dir/$b" ] && cp -p "$dir/$b" "$STAGE/$cli/"
	done
	[ -n "$(ls "$STAGE/$cli")" ] || { echo "no kvo in $dir" >&2; exit 1; }
	cp "$REPO/LICENSE" "$REPO/NOTICE" "$REPO/README.md" "$STAGE/$cli/"
	archive "$kind" "$cli"

	if [ -f "$dir/kevasod" ]; then
		d="kevasod-$VERSION-$plat"
		mkdir -p "$STAGE/$d"
		cp -p "$dir/kevasod" "$STAGE/$d/"
		cp "$REPO/LICENSE" "$REPO/NOTICE" "$STAGE/$d/"
		archive tgz "$d"
	fi
done
[ "$found" = 1 ] || { echo "nothing built in $ROOT" >&2; exit 1; }
