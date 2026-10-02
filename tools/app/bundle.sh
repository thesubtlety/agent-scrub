#!/usr/bin/env bash
# Builds Agent Scrub into .build/AgentScrub.app (unsigned).
#   ./tools/app/bundle.sh              # native build (fast; this machine's architecture)
#   UNIVERSAL=1 ./tools/app/bundle.sh  # universal build (Apple Silicon + Intel), used by the release workflow
set -euo pipefail
cd "$(dirname "$0")/../.."

ARCH_FLAGS=()
[ -n "${UNIVERSAL:-}" ] && ARCH_FLAGS=(--arch arm64 --arch x86_64)

swift build -c release --product HistoryGuardApp ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"}
BINDIR="$(swift build -c release --product HistoryGuardApp ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} --show-bin-path)"

APP=".build/AgentScrub.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINDIR/HistoryGuardApp" "$APP/Contents/MacOS/HistoryGuard"
cp tools/app/Info.plist "$APP/Contents/Info.plist"
[ -e tools/app/AppIcon.icns ] && cp tools/app/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

# SecretDetection ships rules.json as a SwiftPM resource bundle. Bundle.module resolves it from the main
# bundle's resource path or next to the executable, so copy it to both to be safe.
for b in "$BINDIR"/*_SecretDetection.bundle; do
  [ -e "$b" ] || continue
  cp -R "$b" "$APP/Contents/Resources/"
  cp -R "$b" "$APP/Contents/MacOS/"
done

echo "Built $APP (unsigned). First launch: right-click → Open to bypass Gatekeeper."
