#!/usr/bin/env bash
# ClawGuard one-shot installer (daemon + OpenClaw skill + auto-start)
#
# Safe defaults:
# - Installs to ~/.local/bin (no sudo)
# - Creates ~/.clawguard/config.ini and ~/.clawguard/policy.ini (does not overwrite if present)
# - Installs OpenClaw skill into ~/.openclaw/workspace/skills/clawguard (if workspace exists)
# - Adds "allow_skill = clawguard" to policy.ini so the OpenClaw bot can fully automate via guard_exec.py
#
# Remote install pattern (after you publish a repo):
#   curl -fsSL https://raw.githubusercontent.com/<YOU>/<REPO>/main/scripts/install.sh | bash
#
set -euo pipefail

VERSION="1.0.0"
DEFAULT_REPO="YOUR_USERNAME/clawguard"

usage() {
  cat <<'EOF'
ClawGuard installer

Usage:
  scripts/install.sh [options]

Options:
  --system                 Install binary to /usr/local/bin (requires sudo)
  --prefix DIR             Install binary to DIR (default: ~/.local/bin)
  --no-build               Skip building (expects ./clawguard already exists)
  --no-service             Skip installing auto-start (launchd/systemd user service)
  --no-openclaw            Skip installing the OpenClaw skill
  --no-allow-skill         Do not add "allow_skill = clawguard" to ~/.clawguard/policy.ini
  --start                  Start/restart the service after install (default: on)
  --no-start               Do not start/restart the service
  -h, --help               Show help

Environment:
  CLAWGUARD_REPO           GitHub repo (owner/name) for curl-pipe installs when script is not run from a checkout.
  CLAWGUARD_REF            Git ref for curl-pipe installs (default: main).
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SYSTEM_INSTALL=0
PREFIX="${HOME}/.local/bin"
DO_BUILD=1
DO_SERVICE=1
DO_OPENCLAW=1
DO_ALLOW_SKILL=1
DO_START=1

while [ $# -gt 0 ]; do
  case "${1}" in
    --system) SYSTEM_INSTALL=1; PREFIX="/usr/local/bin"; shift ;;
    --prefix) PREFIX="${2:?missing --prefix DIR}"; shift 2 ;;
    --no-build) DO_BUILD=0; shift ;;
    --no-service) DO_SERVICE=0; shift ;;
    --no-openclaw) DO_OPENCLAW=0; shift ;;
    --no-allow-skill) DO_ALLOW_SKILL=0; shift ;;
    --start) DO_START=1; shift ;;
    --no-start) DO_START=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: ${1}" >&2; usage; exit 2 ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"

echo ""
echo "  🦞 ClawGuard v${VERSION} Installer"
echo "  Detected: ${OS} ${ARCH}"
echo ""

need_bin() {
  local b="$1"
  if ! command -v "$b" >/dev/null 2>&1; then
    echo "Error: missing required binary: $b" >&2
    exit 1
  fi
}

file_has() {
  # file_has <file> <extended-regex>
  local file="$1"
  local re="$2"
  grep -Eq "$re" "$file" 2>/dev/null
}

tmpdir=""
cleanup() {
  if [ -n "${tmpdir}" ] && [ -d "${tmpdir}" ]; then
    rm -rf "${tmpdir}" || true
  fi
}
trap cleanup EXIT

# If we are not running from a checkout, fetch the repo into a temp dir.
if [ ! -f "${ROOT_DIR}/Makefile" ] || [ ! -f "${ROOT_DIR}/clawguard.h" ]; then
  REPO="${CLAWGUARD_REPO:-${DEFAULT_REPO}}"
  REF="${CLAWGUARD_REF:-main}"
  if [ -z "${REPO}" ] || [ "${REPO}" = "${DEFAULT_REPO}" ] && [[ "${DEFAULT_REPO}" == YOUR_USERNAME/* ]]; then
    echo "Error: This installer is not running from a local checkout, and the repo is not configured." >&2
    echo "Example:" >&2
    echo "  CLAWGUARD_REPO=\"yourname/clawguard\" curl -fsSL https://raw.githubusercontent.com/yourname/clawguard/main/scripts/install.sh | bash" >&2
    exit 1
  fi
  need_bin curl
  need_bin tar
  tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t clawguard)"
  echo "  Downloading source from GitHub (${REPO}@${REF})..."
  curl -fsSL "https://github.com/${REPO}/archive/${REF}.tar.gz" | tar xz -C "${tmpdir}" --strip-components=1
  ROOT_DIR="${tmpdir}"
fi

DATA_DIR="${HOME}/.clawguard"
CONFIG_FILE="${DATA_DIR}/config.ini"
POLICY_FILE="${DATA_DIR}/policy.ini"
EVENT_LOG="${DATA_DIR}/openclaw-events.jsonl"
ALERT_FILE="${DATA_DIR}/alerts.txt"
LOG_FILE="${DATA_DIR}/clawguard.log"

mkdir -p "${DATA_DIR}"

ensure_kv() {
  # ensure_kv <file> <key> <value>
  # Writes "key = value" and updates existing key.
  local file="$1"
  local key="$2"
  local value="$3"
  if [ ! -f "${file}" ]; then
    printf "%s = %s\n" "${key}" "${value}" >> "${file}"
    return
  fi
  if file_has "${file}" "^[[:space:]]*${key}[[:space:]]*="; then
    # macOS sed requires -i ''.
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${value}|g" "${file}"
    else
      sed -i '' "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${value}|g" "${file}"
    fi
  else
    printf "%s = %s\n" "${key}" "${value}" >> "${file}"
  fi
}

echo "  Preparing config..."
if [ ! -f "${CONFIG_FILE}" ]; then
  cat > "${CONFIG_FILE}" <<EOF
# ClawGuard Configuration
mode = readonly
poll_interval_sec = 5
history_max_minutes = 1440
http_port = 7677
http_bind = 127.0.0.1
allow_remote_http = false
api_auth_token =
api_rate_limit_enabled = true
api_rate_limit_per_min = 120
port_scan_interval_sec = 60
data_dir = ${DATA_DIR}

# OpenClaw attribution + policy
openclaw_event_log_file = ${EVENT_LOG}
openclaw_event_tail_max = 200
policy_file = ${POLICY_FILE}

# Alert Thresholds
cpu_warn_pct = 80
cpu_crit_pct = 95
mem_warn_pct = 80
mem_crit_pct = 95
disk_warn_pct = 85
disk_crit_pct = 95

# OpenClaw Integration
openclaw_alerts = true
alert_file = ${ALERT_FILE}
EOF
  echo "  ✓ Created ${CONFIG_FILE}"
else
  # Backfill keys we rely on (non-destructive).
  need_bin python3
  ensure_kv "${CONFIG_FILE}" "data_dir" "${DATA_DIR}"
  ensure_kv "${CONFIG_FILE}" "mode" "readonly"
  ensure_kv "${CONFIG_FILE}" "http_bind" "127.0.0.1"
  ensure_kv "${CONFIG_FILE}" "allow_remote_http" "false"
  ensure_kv "${CONFIG_FILE}" "api_auth_token" ""
  ensure_kv "${CONFIG_FILE}" "api_rate_limit_enabled" "true"
  ensure_kv "${CONFIG_FILE}" "api_rate_limit_per_min" "120"
  ensure_kv "${CONFIG_FILE}" "openclaw_event_log_file" "${EVENT_LOG}"
  ensure_kv "${CONFIG_FILE}" "openclaw_event_tail_max" "200"
  ensure_kv "${CONFIG_FILE}" "policy_file" "${POLICY_FILE}"
  ensure_kv "${CONFIG_FILE}" "openclaw_alerts" "true"
  ensure_kv "${CONFIG_FILE}" "alert_file" "${ALERT_FILE}"
fi

echo "  Preparing policy..."
if [ ! -f "${POLICY_FILE}" ]; then
  if [ -f "${ROOT_DIR}/policy.example.ini" ]; then
    cp "${ROOT_DIR}/policy.example.ini" "${POLICY_FILE}"
  else
    cat > "${POLICY_FILE}" <<'EOF'
# ClawGuard Trusted Ops Policy
# key = value pairs, repeatable keys.
#
# Allow a skill name to run anything through guard_exec.py without friction:
# allow_skill = clawguard
EOF
  fi
  echo "  ✓ Created ${POLICY_FILE}"
fi

if [ "${DO_ALLOW_SKILL}" -eq 1 ]; then
  if ! file_has "${POLICY_FILE}" "^[[:space:]]*allow_skill[[:space:]]*=[[:space:]]*clawguard[[:space:]]*$"; then
    printf "\nallow_skill = clawguard\n" >> "${POLICY_FILE}"
    echo "  ✓ Added allow_skill = clawguard"
  fi
fi

echo "  Installing binary..."
if [ "${DO_BUILD}" -eq 1 ]; then
  need_bin make
  # clang++ is default on macOS; g++ is common on Linux.
  if ! command -v clang++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1; then
    echo "Error: need a C++ compiler (clang++ or g++) to build from source." >&2
    exit 1
  fi
  (cd "${ROOT_DIR}" && make)
fi

BIN_SRC="${ROOT_DIR}/clawguard"
if [ ! -f "${BIN_SRC}" ]; then
  echo "Error: clawguard binary not found at ${BIN_SRC}" >&2
  echo "Try running with build enabled (default) from a source checkout." >&2
  exit 1
fi

mkdir -p "${PREFIX}"
BIN_DST="${PREFIX}/clawguard"
if [ "${SYSTEM_INSTALL}" -eq 1 ]; then
  sudo install -m 755 "${BIN_SRC}" "${BIN_DST}"
else
  install -m 755 "${BIN_SRC}" "${BIN_DST}"
fi
echo "  ✓ Installed ${BIN_DST}"

if [ "${DO_OPENCLAW}" -eq 1 ]; then
  echo "  Installing OpenClaw skill (if workspace exists)..."
  OC_WORKSPACE="${HOME}/.openclaw/workspace"
  OC_SKILLS_DIR="${OC_WORKSPACE}/skills"
  if [ -d "${OC_WORKSPACE}" ]; then
    mkdir -p "${OC_SKILLS_DIR}/clawguard"
    cp -f "${ROOT_DIR}/skill/clawguard/SKILL.md" "${OC_SKILLS_DIR}/clawguard/SKILL.md"
    cp -f "${ROOT_DIR}/skill/clawguard/BOT_PLAYBOOK.md" "${OC_SKILLS_DIR}/clawguard/BOT_PLAYBOOK.md"
    cp -f "${ROOT_DIR}/skill/clawguard/guard_exec.py" "${OC_SKILLS_DIR}/clawguard/guard_exec.py"
    cp -f "${ROOT_DIR}/skill/clawguard/log_event.py" "${OC_SKILLS_DIR}/clawguard/log_event.py"
    chmod +x "${OC_SKILLS_DIR}/clawguard/guard_exec.py" "${OC_SKILLS_DIR}/clawguard/log_event.py"
    echo "  ✓ Skill installed to ${OC_SKILLS_DIR}/clawguard"
  else
    echo "  (OpenClaw workspace not found at ${OC_WORKSPACE}; skipping skill install)"
  fi
fi

install_service_macos() {
  local plist="${HOME}/Library/LaunchAgents/com.clawguard.plist"
  mkdir -p "${HOME}/Library/LaunchAgents"
  cat > "${plist}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.clawguard</string>

    <key>ProgramArguments</key>
    <array>
      <string>${BIN_DST}</string>
      <string>-c</string>
      <string>${CONFIG_FILE}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${DATA_DIR}/clawguard.out.log</string>
    <key>StandardErrorPath</key>
    <string>${DATA_DIR}/clawguard.err.log</string>
  </dict>
</plist>
EOF

  # Prefer modern launchctl flows; ignore errors if not previously loaded.
  local uid
  uid="$(id -u)"
  launchctl bootout "gui/${uid}" "${plist}" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/${uid}" "${plist}"
  launchctl enable "gui/${uid}/com.clawguard" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/${uid}/com.clawguard" >/dev/null 2>&1 || true
  echo "  ✓ launchd installed (${plist})"
}

install_service_linux_user() {
  local unit_dir="${HOME}/.config/systemd/user"
  local unit="${unit_dir}/clawguard.service"
  mkdir -p "${unit_dir}"
  cat > "${unit}" <<EOF
[Unit]
Description=ClawGuard System Monitor (user)
After=network.target

[Service]
Type=simple
ExecStart=${BIN_DST} -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable clawguard >/dev/null 2>&1 || true
  systemctl --user restart clawguard >/dev/null 2>&1 || systemctl --user start clawguard >/dev/null 2>&1 || true
  echo "  ✓ systemd user service installed (${unit})"
}

if [ "${DO_SERVICE}" -eq 1 ]; then
  echo "  Installing auto-start..."
  if [ "${OS}" = "Darwin" ]; then
    install_service_macos
  elif [ "${OS}" = "Linux" ]; then
    if command -v systemctl >/dev/null 2>&1; then
      install_service_linux_user
    else
      echo "  (systemctl not found; skipping service install)"
    fi
  else
    echo "  (unsupported OS for service install; skipping)"
  fi
fi

if [ "${DO_START}" -eq 1 ]; then
  # On Linux user systems without a user session, restart may fail; fall back to background run.
  if [ "${OS}" = "Linux" ] && [ "${DO_SERVICE}" -eq 0 ]; then
    nohup "${BIN_DST}" -c "${CONFIG_FILE}" > "${LOG_FILE}" 2>&1 & disown || true
  fi
fi

echo ""
echo "  ✅ ClawGuard installed"
echo ""
echo "  Dashboard: http://127.0.0.1:7677"
echo "  Bot summary API: curl -fsS http://127.0.0.1:7677/api/brief"
echo "  Data dir: ${DATA_DIR}"
echo ""
echo "  OpenClaw automation wrapper:"
echo "    python3 skills/clawguard/guard_exec.py --skill clawguard -- -- /usr/bin/uptime"
echo ""
if [ "${OS}" = "Linux" ]; then
  echo "  Note (Linux): if you want the user service to run when you're logged out:"
  echo "    loginctl enable-linger \"${USER}\""
  echo ""
fi
