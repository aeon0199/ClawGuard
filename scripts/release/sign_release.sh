#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
SECRET_KEY="${MINISIGN_SECRET_KEY:-}"
PUBLIC_KEY="${MINISIGN_PUBLIC_KEY:-}"
PUBLISHER_ID="${CLAWGUARD_PUBLISHER_ID:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_TIME_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="unknown"
if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
fi
BUILD_HOST="$(uname -s)-$(uname -m)"
PRODUCT_VERSION="$(awk -F'\"' '/constexpr const char\\* VERSION/ {print $2; exit}' "$REPO_ROOT/clawguard.h" 2>/dev/null || echo unknown)"

if [[ ! -d "$DIST_DIR" ]]; then
  echo "error: dist directory not found: $DIST_DIR" >&2
  exit 1
fi

if [[ -z "$SECRET_KEY" ]]; then
  echo "error: MINISIGN_SECRET_KEY is required for release signing" >&2
  exit 1
fi
if [[ -z "$PUBLIC_KEY" ]]; then
  echo "error: MINISIGN_PUBLIC_KEY is required for release signing" >&2
  exit 1
fi
if [[ ! -f "$SECRET_KEY" ]]; then
  echo "error: MINISIGN_SECRET_KEY file not found: $SECRET_KEY" >&2
  exit 1
fi
if [[ ! -f "$PUBLIC_KEY" ]]; then
  echo "error: MINISIGN_PUBLIC_KEY file not found: $PUBLIC_KEY" >&2
  exit 1
fi
if [[ -z "$PUBLISHER_ID" ]]; then
  echo "error: CLAWGUARD_PUBLISHER_ID is required (for release provenance)" >&2
  exit 1
fi
if ! command -v minisign >/dev/null 2>&1; then
  echo "error: minisign is required for release signing" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1"; }
else
  echo "error: need sha256sum or shasum" >&2
  exit 1
fi

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

(
  cd "$DIST_DIR"
  cat > RELEASE_PROVENANCE.txt <<EOF
ClawGuard Release Provenance
Build-Time-UTC: $BUILD_TIME_UTC
Publisher-ID: $PUBLISHER_ID
Git-Commit: $GIT_COMMIT
Build-Host: $BUILD_HOST
Product-Version: $PRODUCT_VERSION
Signature-Scheme: minisign

Publisher verification notes:
- Verify SHA256SUMS.minisig against minisign.pub.
- Verify this build references an expected Publisher-ID.
EOF
  echo "wrote $DIST_DIR/RELEASE_PROVENANCE.txt"

  find . -maxdepth 1 -type f \
    ! -name "SHA256SUMS" \
    ! -name "SHA256SUMS.minisig" \
    ! -name "minisign.pub" \
    -print | sort > "$tmp_file"

  if [[ ! -s "$tmp_file" ]]; then
    echo "error: no release files found in $DIST_DIR" >&2
    exit 1
  fi

  : > SHA256SUMS
  while IFS= read -r rel; do
    f="${rel#./}"
    hash_file "$f" >> SHA256SUMS
  done < "$tmp_file"

  echo "wrote $DIST_DIR/SHA256SUMS"

  minisign -S -m SHA256SUMS -s "$SECRET_KEY" -x SHA256SUMS.minisig -t "ClawGuard release"
  echo "wrote $DIST_DIR/SHA256SUMS.minisig"
  cp "$PUBLIC_KEY" minisign.pub
  echo "copied public key to $DIST_DIR/minisign.pub"
)
