---
name: clawguard
description: Real-time system health monitoring with proactive alerts. Monitors CPU, memory, disk, network, and processes with trend analysis.
version: 1.0.0
author: ClawGuard
tags: [monitoring, system, health, performance, alerts, devops]
metadata:
  openclaw:
    emoji: 🛡️
    requires:
      bins: [curl, python3]
---

# ClawGuard — System Health Monitor

ClawGuard is a high-performance C++ daemon that continuously monitors your system and provides real-time health data, trend analysis, and proactive alerts.

## What It Monitors
- **CPU**: Usage %, per-core stats, load averages, usage trends
- **Memory**: Used/available, swap, memory leak detection via trends
- **Disk**: All mounted volumes, space usage, fill-rate warnings
- **Network**: Bandwidth in/out with rate calculations
- **Processes**: Top consumers by memory and CPU, total process count
- **Trends**: 30-minute linear regression on CPU and memory to predict issues

## How To Use

## OpenClaw Bot Integration (Recommended)

Use `BOT_PLAYBOOK.md` for first-run onboarding and autonomy mode selection.
The bot should not assume one fixed behavior. It should present mode options and adapt to the host.

If an OpenClaw bot is going to run host commands (even read-only triage), run them through the ClawGuard wrapper so ClawGuard can:

- Log the action to `~/.clawguard/openclaw-events.jsonl` (powers `GET /api/activity` and alert correlation)
- Enforce a simple allowlist in `~/.clawguard/policy.ini`

### Guarded exec (logs + allowlist)

```bash
# Example: list listening ports (allowed by the default starter policy we ship)
python3 skills/clawguard/guard_exec.py --skill clawguard -- -- /usr/sbin/lsof -nP -iTCP -sTCP:LISTEN
```

To permit more commands, add rules to `~/.clawguard/policy.ini`:

```ini
allow_cmd_prefix = /usr/bin/curl
allow_cmd_prefix = /usr/bin/git
allow_cmd_regex = ^curl https://clawguard\\.net
```

### Log-only (no command execution)

```bash
python3 skills/clawguard/log_event.py --skill clawguard --tool http --status ok --command "GET /api/brief"
```

### Check current system status
```bash
curl -s http://localhost:7677/api/current | python3 -m json.tool
```

### Get system information
```bash
curl -s http://localhost:7677/api/system | python3 -m json.tool
```

### Check for alerts
```bash
curl -s http://localhost:7677/api/alerts | python3 -m json.tool
```

### Get bot-friendly summary (Pro)
```bash
curl -s http://localhost:7677/api/brief | python3 -m json.tool
```

### Get recent OpenClaw activity (optional)
```bash
curl -s http://localhost:7677/api/activity | python3 -m json.tool
```

### Get recommended next actions (Pro)
```bash
curl -s http://localhost:7677/api/recommendations | python3 -m json.tool
```

### Check OpenClaw security posture (Pro)
```bash
curl -s http://localhost:7677/api/security | python3 -m json.tool
```

### Check containment state (experimental)
```bash
curl -s http://localhost:7677/api/containment | python3 -m json.tool
```

### Read the alert file directly
```bash
cat ~/.clawguard/alerts.txt
```

### Get trend analysis
```bash
curl -s http://localhost:7677/api/trends | python3 -m json.tool
```

### List listening ports (Pro)
```bash
curl -s http://localhost:7677/api/ports | python3 -m json.tool
```

### Get historical data (last N minutes)
```bash
curl -s "http://localhost:7677/api/history?minutes=60" | python3 -m json.tool
```

### Open the visual dashboard
Open http://localhost:7677 in a browser.

## Proactive Behavior

ClawGuard writes alerts to `~/.clawguard/alerts.txt`. During heartbeat or cron checks, read this file. If it contains WARNING or CRITICAL alerts, proactively notify the user.

Example cron integration:
```bash
# Check every 15 minutes
*/15 * * * * cat ~/.clawguard/alerts.txt | grep -E "WARNING|CRITICAL" && echo "System alert detected"
```

## Security Posture Workflow

When the user asks:
- "Is my OpenClaw setup secure?" -> call `/api/security` and summarize `status`, `openclaw`, `config_findings`, and `integrity`.
- "Anything risky in my config?" -> inspect `config_findings` and prioritize `critical` findings first.
- "Did anything change unexpectedly?" -> inspect `integrity.changed` / `integrity.missing`.
- "Rebaseline trusted files" -> run ClawGuard with `CLAWGUARD_REBASELINE=1` once, then return to normal runs.

## Install-Time UX Requirement

On first use, the bot should:

1. Run a posture snapshot (`/api/brief` and `/api/security`).
2. Offer three autonomy modes (`Manual`, `Assist`, `Autopilot`) from `BOT_PLAYBOOK.md`.
3. Recommend one mode based on host profile.
4. Confirm what actions are automatic versus approval-gated.

## Experimental Containment

Containment exists but is intentionally conservative by default:

- `containment_enabled = false`
- `containment_shadow_mode = true`
- hard actions approval-gated

On setup, the bot should explain containment as optional/experimental and require explicit user opt-in before enforcement.
