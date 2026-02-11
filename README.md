# ClawGuard Lite (Free)

Free, on-demand system health checks for OpenClaw users.

This public repository contains **ClawGuard Lite only**:
- `skill/clawguard-lite/SKILL.md`
- `skill/clawguard-lite/snapshot.py`

## What Lite Does
- Runs a one-shot snapshot of CPU, memory, disk, network, and top processes.
- No daemon, no always-on monitoring, no historical ring buffer.

## Use with OpenClaw
Copy the skill into your OpenClaw workspace and run:

```bash
python3 skill/clawguard-lite/snapshot.py
```

## Pro Version
ClawGuard Pro is distributed separately via the official website and checkout flow.
