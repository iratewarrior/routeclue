#!/bin/bash
# Copies the release CLI to /usr/local/bin (asks for a password).
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release
BIN=".build/release/routeclue"
[ -x "$BIN" ] || { echo "Build failed: $BIN not found" >&2; exit 1; }

sudo install -m 755 "$BIN" /usr/local/bin/routeclue
echo "Installed: $(which routeclue)"
