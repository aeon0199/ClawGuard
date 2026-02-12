#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-.}"
CHECKSUM_FILE="$DIST_DIR/SHA256SUMS"
SIG_FILE="$DIST_DIR/SHA256SUMS.minisig"
PUBKEY_FILE="$DIST_DIR/minisign.pub"

if [[ ! -f "$CHECKSUM_FILE" ]]; then
  echo "error: checksum file not found: $CHECKSUM_FILE" >&2
  exit 1
fi

if [[ -f "$SIG_FILE" ]]; then
  if [[ ! -f "$PUBKEY_FILE" ]]; then
    echo "error: signature exists but public key missing: $PUBKEY_FILE" >&2
    exit 1
  fi
  if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required to verify signature" >&2
    exit 1
  fi
  minisign -Vm "$CHECKSUM_FILE" -x "$SIG_FILE" -p "$PUBKEY_FILE"
fi

(
  cd "$DIST_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS
  else
    echo "error: need sha256sum or shasum" >&2
    exit 1
  fi
)

echo "release verification complete"

