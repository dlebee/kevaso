#!/bin/sh
# A local kvo plugin index (ADR 0008), signed with a key of this checkout's own (bin/plugins/signing.key):
# the example plugin for every OS and CPU kvo supports, and the panes client on macOS. Nothing is
# published; serve the folder on this machine and point kvo at it.
set -eu
cd "$(dirname "$0")/.."
out=bin/plugins
version=${PLUGIN_VERSION:-v0.1.0}
mkdir -p "$out"
rm -f "$out/index.json" "$out/index.json.sig"
idx="go run ./hack/pluginindex"
key=$($idx keygen "$out")

for p in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
	os=${p%/*} arch=${p#*/}
	exe=kvo-whoami
	[ "$os" = windows ] && exe=kvo-whoami.exe
	dir="$out/whoami/$version/$os-$arch"
	mkdir -p "$dir"
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags "-X main.version=$version" -o "$dir/$exe" ./examples/kvo-plugin
	$idx add "$out/index.json" --name whoami --version "$version" --os "$os" --arch "$arch" --kind binary \
		--description "who you are in the current context, and what you can do there" "$dir/$exe"
done

if [ "$(uname -s)" = Darwin ]; then
	make -C apps/panes archive
	arch=$(uname -m); [ "$arch" = x86_64 ] && arch=amd64
	dir="$out/panes/$version/darwin-$arch"
	mkdir -p "$dir"
	cp apps/panes/.build/plugin/panes-darwin.tar.gz "$dir/"
	$idx add "$out/index.json" --name panes --version "$version" --os darwin --arch "$arch" --kind tar.gz \
		--entry "KevasoPanes.app/Contents/MacOS/KevasoPanes" \
		--description "your silos' panes, floating on your desktop" "$dir/panes-darwin.tar.gz"
fi

$idx sign "$out/signing.key" "$out/index.json"
echo
echo "index: $out/index.json (signed; key $key)"
echo "serve it:   python3 -m http.server -d $out 8765"
echo "then:       KVO_PLUGIN_INDEX=http://127.0.0.1:8765/index.json KVO_PLUGIN_INDEX_KEY=$key kvo plugin install panes"
