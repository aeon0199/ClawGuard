#!/usr/bin/env python3
"""
Append a single OpenClaw activity event to ClawGuard's JSONL log.

This is intentionally tiny and dependency-free so OpenClaw can call it from a skill.

Example:
  python3 log_event.py --skill my-skill --tool exec --status start --command "ls -la" --cid abc123
"""
import argparse
import json
import os
import time


def default_path() -> str:
    data_dir = os.path.join(os.path.expanduser("~"), ".clawguard")
    return os.path.join(data_dir, "openclaw-events.jsonl")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=default_path())
    ap.add_argument("--skill", default="")
    ap.add_argument("--tool", default="")
    ap.add_argument("--status", default="info")
    ap.add_argument("--command", default="")
    ap.add_argument("--cid", "--correlation-id", dest="cid", default="")
    args = ap.parse_args()

    evt = {
        "ts_ms": int(time.time() * 1000),
        "skill": args.skill,
        "tool": args.tool,
        "command": args.command,
        "status": args.status,
        "correlation_id": args.cid,
    }

    os.makedirs(os.path.dirname(args.path), exist_ok=True)
    with open(args.path, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, separators=(",", ":"), ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

