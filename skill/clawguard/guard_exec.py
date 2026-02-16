#!/usr/bin/env python3
"""
Optional wrapper: enforce a simple trusted-ops allowlist before running a command,
and log the decision to ClawGuard's OpenClaw JSONL log.

Usage:
  python3 guard_exec.py --skill my-skill --policy ~/.clawguard/policy.ini -- -- ls -la
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time


def default_event_path() -> str:
    data_dir = os.path.join(os.path.expanduser("~"), ".clawguard")
    return os.path.join(data_dir, "openclaw-events.jsonl")


def parse_policy(path: str) -> dict:
    pol = {
        "allow_skill": set(),
        "allow_cmd_prefix": [],
        "allow_cmd_regex": [],
    }
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = [x.strip() for x in line.split("=", 1)]
                if k == "allow_skill" and v:
                    pol["allow_skill"].add(v)
                elif k == "allow_cmd_prefix" and v:
                    pol["allow_cmd_prefix"].append(v)
                elif k == "allow_cmd_regex" and v:
                    pol["allow_cmd_regex"].append(v)
    except FileNotFoundError:
        pass
    return pol


def allowed(pol: dict, skill: str, cmd: str) -> bool:
    if skill and pol["allow_skill"] and skill in pol["allow_skill"]:
        return True
    for pfx in pol["allow_cmd_prefix"]:
        if cmd.startswith(pfx):
            return True
    for pat in pol["allow_cmd_regex"]:
        try:
            if re.search(pat, cmd):
                return True
        except re.error:
            continue
    return False


def log_event(path: str, skill: str, tool: str, status: str, command: str) -> None:
    evt = {
        "ts_ms": int(time.time() * 1000),
        "skill": skill,
        "tool": tool,
        "command": command,
        "status": status,
        "correlation_id": "",
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, separators=(",", ":"), ensure_ascii=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill", default="")
    ap.add_argument("--policy", default=os.path.join(os.path.expanduser("~"), ".clawguard", "policy.ini"))
    ap.add_argument("--event-log", default=default_event_path())
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="Command after --")
    args = ap.parse_args()

    # Users often pass `-- -- <cmd>` (first `--` ends argparse options; second is a visual separator).
    # Be forgiving and strip one or more leading `--` tokens.
    while args.cmd and str(args.cmd[0]).strip() == "--":
        args.cmd = args.cmd[1:]
    if not args.cmd:
        print("No command provided. Use: guard_exec.py -- -- <command>", file=sys.stderr)
        return 2

    cmd_str = " ".join(shlex.quote(x) for x in args.cmd)
    pol = parse_policy(args.policy)

    is_allowed = allowed(pol, args.skill, cmd_str)
    if args.debug:
        print(f"[guard_exec] skill={args.skill!r}", file=sys.stderr)
        print(f"[guard_exec] policy={args.policy}", file=sys.stderr)
        print(f"[guard_exec] event_log={args.event_log}", file=sys.stderr)
        print(f"[guard_exec] cmd={cmd_str}", file=sys.stderr)
        print(f"[guard_exec] allow_skill={sorted(pol['allow_skill'])}", file=sys.stderr)
        print(f"[guard_exec] allow_cmd_prefix={pol['allow_cmd_prefix']}", file=sys.stderr)
        print(f"[guard_exec] allow_cmd_regex={pol['allow_cmd_regex']}", file=sys.stderr)
        print(f"[guard_exec] allowed={is_allowed}", file=sys.stderr)

    if not is_allowed:
        log_event(args.event_log, args.skill, "exec", "denied", cmd_str)
        print("Denied by policy. Add an allow_skill/allow_cmd_prefix/allow_cmd_regex rule to proceed.", file=sys.stderr)
        return 77

    log_event(args.event_log, args.skill, "exec", "start", cmd_str)
    try:
        p = subprocess.run(args.cmd, check=False)
        log_event(args.event_log, args.skill, "exec", "ok" if p.returncode == 0 else "error", cmd_str)
        return p.returncode
    except Exception:
        log_event(args.event_log, args.skill, "exec", "error", cmd_str)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
