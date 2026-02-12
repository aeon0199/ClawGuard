#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
SECRET_KEY="${MINISIGN_SECRET_KEY:-}"
PUBLIC_KEY="${MINISIGN_PUBLIC_KEY:-}"

if [[ ! -d "$DIST_DIR" ]]; then
  echo "error: dist directory not found: $DIST_DIR" >&2
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

  if [[ -n "$SECRET_KEY" ]]; then
    if ! command -v minisign >/dev/null 2>&1; then
      echo "error: MINISIGN_SECRET_KEY is set but minisign is not installed" >&2
      exit 1
    fi
    minisign -S -m SHA256SUMS -s "$SECRET_KEY" -x SHA256SUMS.minisig -t "ClawGuard release"
    echo "wrote $DIST_DIR/SHA256SUMS.minisig"
    if [[ -n "$PUBLIC_KEY" ]]; then
      cp "$PUBLIC_KEY" minisign.pub
      echo "copied public key to $DIST_DIR/minisign.pub"
    fi
  else
    echo "note: MINISIGN_SECRET_KEY not set; skipped signature file"
  fi
)
