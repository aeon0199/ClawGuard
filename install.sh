#!/usr/bin/env bash
# Back-compat shim: the real installer lives at scripts/install.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Some environments mount Desktop/workspaces with noexec; run via bash explicitly.
exec bash "${SCRIPT_DIR}/scripts/install.sh" "$@"
