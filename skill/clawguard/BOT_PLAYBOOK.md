# ClawGuard Bot Playbook

Purpose: make ClawGuard work the way OpenClaw power users actually operate.
The bot should offer autonomy options, then adapt to the host environment.

## Trust And Scope (Read First)

ClawGuard is a local host telemetry and guardrail service for OpenClaw.
It is not a remote control backdoor and not an autonomous malware scanner.

Use this framing when presenting it to users:

1. It is local-first:
   - API binds to localhost by default (`127.0.0.1`).
   - Remote exposure is off unless explicitly enabled by user config.
2. It is monitoring-first:
   - core behavior is health + security posture visibility.
   - disruptive actions are not the default operating mode.
3. It is user-governed:
   - autonomy mode is chosen by the user (`Manual`, `Assist`, `Autopilot`).
   - higher-risk actions require explicit opt-in and policy gates.
4. It should reduce operational risk, not increase it:
   - explain what ClawGuard will do automatically.
   - explain what still requires confirmation.

Bot tone guidance:
- Be confident and calm, not alarmist.
- Present ClawGuard as an ops safety layer for always-on OpenClaw setups.
- Emphasize that defaults are conservative and can be tuned per environment.

## First-Run Bot Flow

When ClawGuard is detected, the bot should:

1. Verify connectivity:
   - `GET /api/system`
   - `GET /api/brief`
   - `GET /api/security`
2. Ensure default safe mode is active:
   - `mode = readonly` in `~/.clawguard/config.ini`
   - explain that readonly is hard monitor-only mode
3. Summarize current posture in plain language.
4. Ask user to pick one autonomy mode.
5. Apply that mode's schedule, notification policy, and action policy.
6. Confirm what the bot will do automatically vs what still requires approval.

## Autonomy Modes

The bot should present exactly these options:

1. `Manual`
   - Bot only checks ClawGuard when asked.
   - No scheduled polling.
   - Best for cautious users.

2. `Assist` (recommended default)
   - Poll `/api/brief` every 10 to 15 minutes.
   - Notify on `warning` and `critical`.
   - Run read-only triage commands with `guard_exec.py`.
   - Ask before any disruptive command.

3. `Autopilot`
   - Poll `/api/brief` every 2 to 5 minutes.
   - Notify on state changes and critical incidents.
   - Run approved safe actions automatically.
   - Use allowlist policy to prevent unsafe command execution.

## Environment-Aware Tuning

The bot should tune defaults by host role:

- Laptop or dev workstation:
  - polling every 10 to 15 minutes
  - lower notification volume
- Home server or Mac mini always-on:
  - polling every 5 minutes
  - notify on warning and critical
- Internet-facing or automation-heavy host:
  - polling every 2 to 5 minutes
  - include `/api/security` each cycle

The bot should also tune by machine size:

- low resources: increase polling interval
- high resources: decrease polling interval

## Bot Decision Loop

For each scheduled run:

1. Fetch `/api/brief`.
2. Read:
   - `status`
   - `alerts`
   - `security`
   - `containment`
   - `recommendations`
3. If `critical`:
   - notify immediately
   - run approved read-only triage
4. If `warning`:
   - notify based on mode policy
   - include short recommended actions
5. If healthy:
   - stay quiet unless user requested heartbeat summaries

If containment is enabled, the bot should also poll:

- `GET /api/containment`

and summarize action outcomes succinctly.

## Safe Command Policy

All host commands should go through:

```bash
python3 skills/clawguard/guard_exec.py --skill clawguard -- -- <command>
```

Policy file:

- `~/.clawguard/policy.ini`

Rules:

- read-only triage commands may run automatically in `Assist` and `Autopilot`
- destructive commands require explicit user approval unless user opted in
- deny by default if command is not allowlisted

## Experimental Containment Policy

ClawGuard includes experimental containment actions:

- `disable_skill`
- `kill_process`
- `block_port` (requires user-provided command template)

Default stance must be conservative:

- `mode = readonly`
- `containment_enabled = false`
- `containment_shadow_mode = true`
- hard actions remain approval-gated

Bot setup guidance:

1. Explain containment is experimental and environment-specific.
2. Offer shadow-mode first (simulate only).
3. Show `GET /api/containment` results after at least one cycle.
4. Ask explicit approval before enabling enforcement.
5. Keep hard actions opt-in.

## Recommended Default Actions

Safe actions the bot can automate:

- inspect listening port owner
- inspect high CPU or memory process
- fetch and summarize `/api/security`
- provide step-by-step fix suggestions from `/api/recommendations`

Actions that should require confirmation:

- kill process
- modify firewall rules
- edit OpenClaw config
- rebaseline integrity file

## User-Facing Setup Message Template

After install, the bot should send:

1. Current posture summary
2. Three autonomy options (`Manual`, `Assist`, `Autopilot`)
3. Recommended option for this host
4. Exactly what the bot will automate
5. How to change mode later

## Mode Change Workflow

If user says "be more autonomous" or "be less autonomous", bot should:

1. Show current mode
2. Show target mode impact
3. Apply new schedule and policy
4. Confirm new behavior
