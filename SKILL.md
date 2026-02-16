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

For bot-first behavior, follow:

- `skill/clawguard/BOT_PLAYBOOK.md`

## What It Monitors
- **CPU**: Usage %, per-core stats, load averages, usage trends
- **Memory**: Used/available, swap, memory leak detection via trends
- **Disk**: All mounted volumes, space usage, fill-rate warnings
- **Network**: Bandwidth in/out with rate calculations
- **Processes**: Top consumers by memory, total process count
- **Trends**: 30-minute linear regression on CPU and memory to predict issues

## How To Use

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

### Get bot-friendly summary
```bash
curl -s http://localhost:7677/api/brief | python3 -m json.tool
```

### Get recent OpenClaw activity (optional)
```bash
curl -s http://localhost:7677/api/activity | python3 -m json.tool
```

### Get recommended next actions
```bash
curl -s http://localhost:7677/api/recommendations | python3 -m json.tool
```

### Check OpenClaw security posture
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

### List listening ports
```bash
curl -s http://localhost:7677/api/ports | python3 -m json.tool
```

### Get historical data (last N minutes)
```bash
curl -s "http://localhost:7677/api/history?minutes=60" | python3 -m json.tool
```

### Open the visual dashboard
Open http://localhost:7677 in a browser.

## Alert Thresholds
Default thresholds (configurable in ~/.clawguard/config.ini):
- CPU Warning: 80%, Critical: 95%
- Memory Warning: 80%, Critical: 95%
- Disk Warning: 85%, Critical: 95%

## When To Use These Tools

When the user asks:
- "How's my system doing?" → Fetch /api/current and /api/alerts, summarize health
- "Is anything wrong?" → Check /api/alerts for active warnings
- "How's my memory/CPU trending?" → Fetch /api/trends for direction analysis
- "Show me system history" → Fetch /api/history for time-series data
- "What's eating my RAM/CPU?" → Fetch /api/current and look at top processes
- "How much disk space do I have?" → Fetch /api/current and check disks array
- "Is my system healthy?" → Combine /api/current + /api/alerts + /api/trends
- "Is OpenClaw secure?" → Fetch /api/security and summarize posture + recommended actions
- "Should I enable containment?" → Fetch /api/containment and explain shadow-mode first

On first install, do not force one behavior model. Offer autonomy mode options from `BOT_PLAYBOOK.md` and let the user choose.

## Proactive Behavior

ClawGuard writes alerts to `~/.clawguard/alerts.txt`. During heartbeat or cron checks, read this file. If it contains WARNING or CRITICAL alerts, proactively notify the user.

Example cron integration:
```bash
# Check every 15 minutes
*/15 * * * * cat ~/.clawguard/alerts.txt | grep -E "WARNING|CRITICAL" && echo "System alert detected"
```

## Installation

```bash
# Clone and build
git clone https://github.com/YOUR_USERNAME/clawguard.git
cd clawguard
make
sudo make install

# Or run directly
./clawguard

# Run as background service
nohup clawguard &

# With custom port
clawguard --port 8080

# With custom poll interval
clawguard --interval 10
```

## API Reference

| Endpoint | Description |
|---|---|
| `GET /` | Web dashboard |
| `GET /api/current` | Current metrics snapshot |
| `GET /api/system` | System information |
| `GET /api/alerts` | Active alerts |
| `GET /api/security` | OpenClaw security posture |
| `GET /api/containment` | Experimental containment status and history |
| `GET /api/trends` | 30-min trend analysis |
| `GET /api/history?minutes=N` | Historical data points |
