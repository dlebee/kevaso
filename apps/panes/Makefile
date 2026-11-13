# The panes client as kvo's `panes` plugin (core ADR 0008): an app bundle, so notifications and the
# keychain work, packed as the archive the plugin index lists for macOS. Ad-hoc signed for now;
# README.md says what signing and notarisation need.
VERSION ?= 0.1.0
OUT     := .build/plugin
APP     := $(OUT)/KevasoPanes.app

.PHONY: app archive

app:                       ## .build/plugin/KevasoPanes.app, for this Mac's CPU
	swift build -c release --product KevasoPanes
	rm -rf .build/plugin/KevasoPanes.app
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp "$$(swift build -c release --show-bin-path)/KevasoPanes" $(APP)/Contents/MacOS/KevasoPanes
	cp Support/Info.plist $(APP)/Contents/Info.plist
	plutil -replace CFBundleShortVersionString -string $(VERSION) $(APP)/Contents/Info.plist
	plutil -replace CFBundleVersion -string $(VERSION) $(APP)/Contents/Info.plist
	codesign --force --sign - --identifier com.kevaso.panes $(APP)

archive: app               ## .build/plugin/panes-darwin.tar.gz: the app at the top; entry KevasoPanes.app/Contents/MacOS/KevasoPanes
	cd $(OUT) && COPYFILE_DISABLE=1 tar --no-xattrs -czf panes-darwin.tar.gz KevasoPanes.app
	@shasum -a 256 $(OUT)/panes-darwin.tar.gz
