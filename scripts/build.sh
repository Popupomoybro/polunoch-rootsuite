#!/bin/sh
# RootSuite — one app, every root path, selectable.
# Cross-compiled with clang for arm64 iOS exactly like the previous working app
# (no Xcode project needed, so the build is reproducible on a CI macOS runner).
set -e
cd "$(dirname "$0")/.."
APP=RootSuite
BUNDLE=ask.polunoch.ave2trigger.5G33ZSZ4G5   # the only id the Sideloadly profile covers
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT=out
mkdir -p "$OUT/Payload/$APP.app/Frameworks"

clang -isysroot "$SDK" -target arm64-apple-ios15.0 -O1 \
  -framework UIKit -framework Foundation -framework WebKit -framework JavaScriptCore -framework CoreGraphics \
  -framework IOSurface -framework IOKit -framework CoreServices \
  Sources/main.m Sources/AppDelegate.m Sources/Modules.m Sources/Root.m Sources/WebKitProbes.m Sources/WorseQuery.m Sources/RootPaths.m Sources/RootPaths2.m Sources/LastMile.m Sources/KernelPaths.m Sources/Scribble.m Sources/Unified.m \
  -o "$OUT/Payload/$APP.app/$APP"

cp Resources/Info.plist        "$OUT/Payload/$APP.app/"
cp Resources/entitlements.plist "$OUT/Payload/$APP.app/"
cp Resources/*.js              "$OUT/Payload/$APP.app/"    # the JSC scripts, loaded at run time
cp Resources/libexports.dylib  "$OUT/Payload/$APP.app/" 2>/dev/null || true
cp Resources/libclient.dylib   "$OUT/Payload/$APP.app/" 2>/dev/null || true
cp Resources/Frameworks/libmalformed.dylib "$OUT/Payload/$APP.app/Frameworks/" 2>/dev/null || true

# ad-hoc signature over everything (Sideloadly re-signs on install anyway)
codesign -s - --force "$OUT/Payload/$APP.app/libexports.dylib" 2>/dev/null || true
codesign -s - --force "$OUT/Payload/$APP.app/libclient.dylib" 2>/dev/null || true
codesign -s - --force --no-strict "$OUT/Payload/$APP.app/Frameworks/libmalformed.dylib" 2>/dev/null || true
codesign -s - --force --entitlements Resources/entitlements.plist "$OUT/Payload/$APP.app/$APP" 2>/dev/null \
  || codesign -s - --force "$OUT/Payload/$APP.app/$APP"

rm -f "$OUT/$APP.ipa"
(cd "$OUT" && zip -qr "$APP.ipa" Payload)
echo "built: $OUT/$APP.ipa ($(du -h "$OUT/$APP.ipa" | cut -f1))"
