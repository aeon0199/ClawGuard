#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macos_verify_provenance.sh must be run on macOS" >&2
  exit 1
fi

BIN_PATH="${1:-}"
EXPECTED_CN="${CLAWGUARD_EXPECTED_CODESIGN_CN:-}"
REQUIRE_NOTARIZED="${CLAWGUARD_REQUIRE_NOTARIZED:-0}"

if [[ -z "$BIN_PATH" ]]; then
  echo "usage: $0 /path/to/clawguard" >&2
  exit 2
fi
if [[ ! -f "$BIN_PATH" ]]; then
  echo "error: binary not found: $BIN_PATH" >&2
  exit 1
fi

if ! command -v codesign >/dev/null 2>&1; then
  echo "error: codesign not found" >&2
  exit 1
fi
if ! command -v spctl >/dev/null 2>&1; then
  echo "error: spctl not found" >&2
  exit 1
fi

echo "[1/3] Verifying signature integrity..."
codesign --verify --strict --verbose=2 "$BIN_PATH"

echo "[2/3] Extracting signer metadata..."
CS_OUT="$(codesign -dv --verbose=4 "$BIN_PATH" 2>&1 || true)"
printf '%s\n' "$CS_OUT" | grep -E "^Authority=|^TeamIdentifier=|^Identifier=" || true

if [[ -n "$EXPECTED_CN" ]]; then
  if ! printf '%s\n' "$CS_OUT" | grep -Fq "Authority=Developer ID Application: $EXPECTED_CN"; then
    echo "error: signing authority mismatch; expected Developer ID CN: $EXPECTED_CN" >&2
    exit 1
  fi
fi

echo "[3/3] Verifying Gatekeeper assessment..."
SP_OUT="$(spctl -a -vv "$BIN_PATH" 2>&1 || true)"
printf '%s\n' "$SP_OUT"

if [[ "$REQUIRE_NOTARIZED" == "1" ]]; then
  if ! printf '%s\n' "$SP_OUT" | grep -Fqi "Notarized"; then
    echo "error: notarization not detected in spctl output" >&2
    exit 1
  fi
fi

echo "macOS provenance verification complete"
