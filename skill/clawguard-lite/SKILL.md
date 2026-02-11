---
name: clawguard-lite
description: On-demand system health checks (no daemon). Uses built-in OS commands to report CPU, memory, disk, network, and top processes.
version: 1.0.0
author: ClawGuard
tags: [monitoring, system, health, performance, free]
metadata:
  openclaw:
    emoji: 🦞
    requires:
      bins: [python3]
---

# ClawGuard Lite — On-Demand System Checks

This is the free, no-daemon version of ClawGuard. It runs a quick snapshot using built-in OS commands and prints a single JSON object you can summarize.

## Run A Snapshot

From this skill directory:
```bash
python3 snapshot.py
```

## What To Do With The Output

When the user asks:
- "How's my system doing?" -> run `python3 snapshot.py`, summarize CPU/mem/disk, and call out any big offenders in top CPU or top memory.
- "What's eating my CPU/RAM?" -> use `processes.top_cpu` / `processes.top_mem`.
- "How much disk space do I have left?" -> use `disks[*].available_bytes` and `disks[*].usage_pct`.

## Notes

- This is **on-demand only**: it does not run in the background, store history, or provide a dashboard.
- For always-on sampling, history/trends, alerts, and the live dashboard, use the ClawGuard daemon skill.

