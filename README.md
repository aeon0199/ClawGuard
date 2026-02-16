# 🦞 ClawGuard

**High-performance system monitor built for the OpenClaw ecosystem.**

<img src="assets/clawguard-logo.jpg" alt="ClawGuard Logo" width="420" />

ClawGuard is a lightweight C++ daemon that continuously monitors your system's health and integrates natively with OpenClaw. Ask your bot "how's my system doing?" and get real answers with trend analysis and proactive alerts.

![ClawGuard Dashboard](https://img.shields.io/badge/dashboard-localhost:7677-ff3355)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Why ClawGuard?

If you run OpenClaw on a Mac Mini, home server, or VPS, you need to know:

- **Is my system healthy?** CPU, memory, disk, network at a glance
- **Is something going wrong?** Proactive alerts before things break
- **What's the trend?** Memory leak detection, CPU trending, disk fill rate
- **What's eating resources?** Top processes by memory and CPU

Other monitoring tools are bloated Python scripts that eat the resources they're supposed to monitor. ClawGuard is written in C++ — it uses **<1% CPU and <5MB RAM** while running 24/7.

## Quick Start

```bash
# Build locally
git clone https://github.com/YOUR_USERNAME/clawguard.git
cd clawguard
make

# Install (user-level, no sudo) + auto-start + OpenClaw skill
bash ./scripts/install.sh
```

Open **http://localhost:7677** for the live dashboard.

### One-line Install (after you publish on GitHub)

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/clawguard/main/scripts/install.sh | bash
```

## OpenClaw Integration

ClawGuard was built for OpenClaw. Install the skill:

```bash
# Auto-detected during ./scripts/install.sh, or manually:
mkdir -p ~/.openclaw/workspace/skills
cp -r skill/clawguard ~/.openclaw/workspace/skills/
```

Bot-first setup guide:
- `skill/clawguard/BOT_PLAYBOOK.md`
- offers `Manual`, `Assist`, and `Autopilot` autonomy modes and adapts by host profile

Now you can ask your OpenClaw bot:
- *"How's my system doing?"*
- *"Is anything wrong with my server?"*
- *"What's eating my RAM?"*
- *"How's my CPU trending?"*
- *"How much disk space do I have left?"*

### Proactive Alerts

ClawGuard writes alerts to `~/.clawguard/alerts.txt`. Configure a cron job in OpenClaw to check it:

```
"Check ~/.clawguard/alerts.txt every 15 minutes. If there are WARNING or CRITICAL alerts, let me know on Telegram."
```

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Live web dashboard |
| `GET /api/current` | Current metrics snapshot |
| `GET /api/system` | System info (hostname, OS, RAM, uptime) |
| `GET /api/alerts` | Active alerts list |
| `GET /api/security` | OpenClaw version/config/integrity posture |
| `GET /api/containment` | Experimental containment state and action history |
| `GET /api/activity` | Recent OpenClaw activity events (optional) |
| `GET /api/recommendations` | Suggested next actions (bot-friendly) |
| `GET /api/brief` | One-shot summary for bots (status + alerts + security + containment + recs + activity) |
| `GET /api/trends` | 30-min CPU/memory trend analysis |
| `GET /api/history?minutes=N` | Historical time-series data |
| `GET /api/ports` | Listening TCP ports (best-effort) |

## Configuration

Edit `~/.clawguard/config.ini`:

```ini
# Monitoring
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

# Security posture checks
security_scan_interval_sec = 60
openclaw_config_file = /Users/you/.openclaw/openclaw.json
integrity_baseline_file = /Users/you/.clawguard/integrity-baseline.txt

# Experimental containment (default-off)
containment_enabled = false
containment_shadow_mode = true
containment_auto_soft_actions = false
containment_auto_hard_actions = false
containment_require_user_approval_for_hard = true
containment_block_ttl_sec = 900
containment_max_actions_per_hour = 6

# Alert Thresholds
cpu_warn_pct = 80
cpu_crit_pct = 95
mem_warn_pct = 80
mem_crit_pct = 95
disk_warn_pct = 85
disk_crit_pct = 95

# OpenClaw Integration
openclaw_alerts = true
```

Rebuild integrity baseline after expected config/skill changes:
```bash
CLAWGUARD_REBASELINE=1 ./clawguard
```

Experimental containment notes:
- `mode = readonly` is a hard monitor-only gate and disables containment execution.
- Start with `containment_enabled = true` and `containment_shadow_mode = true`.
- Review simulated actions in `GET /api/containment` before enabling enforcement.
- Keep hard actions approval-gated unless user explicitly opts in.
- `block_port` shell-command execution is disabled in v1.0 for safety.

Remote API notes:
- Default is local-only (`http_bind = 127.0.0.1`).
- Non-loopback bind is refused unless `allow_remote_http = true`.
- When remote bind is enabled, `api_auth_token` is required and must be sent as:
  - `Authorization: Bearer <token>` or
  - `X-API-Key: <token>`
- API rate limiting is enabled by default (`api_rate_limit_per_min = 120` per client).
- Dashboard responses include a restrictive Content Security Policy (CSP).

## Verify Downloads (SHA-256 + Minisign)
Publisher flow:
```bash
# requires MINISIGN_SECRET_KEY, MINISIGN_PUBLIC_KEY, CLAWGUARD_PUBLISHER_ID
./scripts/release/sign_release.sh dist
```

User verification flow:
```bash
./scripts/release/verify_release.sh dist
```

Required signing inputs for publishers:
- `MINISIGN_SECRET_KEY=/path/to/minisign.key`
- `MINISIGN_PUBLIC_KEY=/path/to/minisign.pub`
- `CLAWGUARD_PUBLISHER_ID=clawguard.net` (or your stable publisher identity string)

Optional stricter verification for users:
- `CLAWGUARD_EXPECTED_PUBLISHER_ID=clawguard.net ./scripts/release/verify_release.sh dist`

## macOS Signing and Notarization (Publisher)

```bash
# Sign only (Developer ID)
APPLE_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
./scripts/release/macos_sign_and_notarize.sh ./clawguard

# Sign + notarize (when notary profile is configured)
APPLE_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
APPLE_NOTARY_PROFILE="clawguard-notary" \
APPLE_TEAM_ID="TEAMID" \
./scripts/release/macos_sign_and_notarize.sh ./clawguard ./clawguard.notarized.zip
```

User-side macOS provenance check:
```bash
./scripts/release/macos_verify_provenance.sh ./clawguard
```

## Run as a Service

```bash
# Linux (systemd user service, installed automatically by scripts/install.sh)
systemctl --user status clawguard

# macOS (launchd user agent, installed automatically by scripts/install.sh)
launchctl list | rg clawguard
```

## Architecture

```
┌──────────────────────────────────┐
│         ClawGuard Daemon         │
├──────────┬───────────┬───────────┤
│ Collector│  History  │  Alerts   │
│ (C++ OS  │ (Ring Buf)│ (Engine)  │
│  APIs)   │ 24h data  │ + Trends  │
├──────────┴───────────┴───────────┤
│          HTTP Server             │
│   JSON API  +  Web Dashboard     │
├──────────────────────────────────┤
│       OpenClaw Skill Layer       │
│  SKILL.md  +  alerts.txt file    │
└──────────────────────────────────┘
```

- **Collector**: Reads `/proc` (Linux) or Mach APIs (macOS) directly — no shell commands for core metrics
- **History**: Lock-free ring buffer holding 24h of 5-second samples (~17K snapshots)
- **Alerts**: Threshold evaluation with 5-minute cooldown, writes to file for OpenClaw
- **HTTP**: Minimal embedded server, no dependencies, serves JSON API + single-page dashboard
- **Footprint**: Single static binary, no runtime dependencies, <5MB RAM

## Building from Source

Requirements: `g++` with C++17 support, `make`

```bash
make              # Build
make clean        # Clean
sudo make install # Install to /usr/local/bin
```

Or with CMake:
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Platforms

| Platform | Status |
|---|---|
| Linux (x86_64) | ✅ Full support |
| Linux (ARM64) | ✅ Full support |
| macOS (Apple Silicon) | ✅ Full support |
| macOS (Intel) | ✅ Full support |

## License

Proprietary commercial license. See [LICENSE](LICENSE) for details.

---

**Built with 🦞 for the OpenClaw community.**
