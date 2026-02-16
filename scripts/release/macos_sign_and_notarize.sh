#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macos_sign_and_notarize.sh must be run on macOS" >&2
  exit 1
fi

BIN_PATH="${1:-}"
OUT_ZIP="${2:-}"
IDENTITY="${APPLE_CODESIGN_IDENTITY:-}"
NOTARY_PROFILE="${APPLE_NOTARY_PROFILE:-}"
TEAM_ID="${APPLE_TEAM_ID:-}"

if [[ -z "$BIN_PATH" ]]; then
  echo "usage: $0 /path/to/clawguard [out-zip]" >&2
  exit 2
fi
if [[ ! -f "$BIN_PATH" ]]; then
  echo "error: binary not found: $BIN_PATH" >&2
  exit 1
fi
if [[ -z "$IDENTITY" ]]; then
  echo "error: APPLE_CODESIGN_IDENTITY is required" >&2
  exit 1
fi
if ! command -v codesign >/dev/null 2>&1; then
  echo "error: codesign not found" >&2
  exit 1
fi

echo "[1/4] Signing binary with Developer ID identity..."
codesign --force --timestamp --options runtime --sign "$IDENTITY" "$BIN_PATH"

echo "[2/4] Verifying local signature..."
codesign --verify --strict --verbose=2 "$BIN_PATH"
spctl -a -vv "$BIN_PATH" || true
codesign -dv --verbose=4 "$BIN_PATH" 2>&1 | sed -n '1,40p'

if [[ -z "$NOTARY_PROFILE" ]]; then
  echo "[3/4] Skipping notarization (APPLE_NOTARY_PROFILE not set)."
  echo "done: signed binary only"
  exit 0
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "error: xcrun is required for notarytool" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_PATH="$TMP_DIR/$(basename "$BIN_PATH").zip"
if [[ -z "$OUT_ZIP" ]]; then
  OUT_ZIP="$(pwd)/$(basename "$BIN_PATH").notarized.zip"
fi

echo "[3/4] Creating notarization archive..."
ditto -c -k --keepParent "$BIN_PATH" "$ZIP_PATH"

echo "[4/4] Submitting to Apple notarization service..."
if [[ -n "$TEAM_ID" ]]; then
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --team-id "$TEAM_ID" --wait
else
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
fi

cp "$ZIP_PATH" "$OUT_ZIP"
echo "done: notarized archive saved to $OUT_ZIP"
