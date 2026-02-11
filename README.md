# ClawGuard Lite (Free)

Free, on-demand system health checks for OpenClaw users.

This public repository contains **ClawGuard Lite only**:
- `skill/clawguard-lite/SKILL.md`
- `skill/clawguard-lite/snapshot.py`

## What Lite Does
- Runs a one-shot snapshot of CPU, memory, disk, network, and top processes.
- Great for quick check-ins when you ask your OpenClaw bot for system status.
- No daemon, no always-on monitoring, no historical ring buffer.

## Use with OpenClaw
Copy the skill into your OpenClaw workspace and run:

```bash
python3 skill/clawguard-lite/snapshot.py
```

## Want The Full Power Version?

## ClawGuard Pro
If Lite is the quick pulse check, **ClawGuard Pro** is full-time system defense.

With Pro you get:
- Always-on daemon monitoring (24/7)
- Live local dashboard
- Historical data + trend analysis
- Proactive alerts
- Port/watchdog detection and richer OpenClaw integrations

Get ClawGuard Pro here:
**https://clawguard.net**

---
Built for OpenClaw users who want their bot to run the machine with confidence.
