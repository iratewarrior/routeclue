#!/bin/bash
# Builds a menu bar .app bundle from the SwiftPM executable.
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${1:-release}"
swift build -c "$CONFIG"
BIN=".build/$CONFIG/RouteClueApp"
[ -x "$BIN" ] || { echo "Build failed: $BIN not found" >&2; exit 1; }

APP="dist/RouteClue.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/RouteClue"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>RouteClue</string>
    <key>CFBundleDisplayName</key><string>RouteClue</string>
    <key>CFBundleIdentifier</key><string>dev.routeclue.app</string>
    <key>CFBundleExecutable</key><string>RouteClue</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.2.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# Ad-hoc signature: enough for local use, not for distribution.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
echo "Built $APP"
