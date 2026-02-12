# ClawGuard Pro

### The version OpenClaw power users actually want.

<img src="assets/clawguard-logo.jpg" alt="ClawGuard Logo" width="420" />

If you run OpenClaw on a real machine (Mac mini, Linux box, VPS), you don’t want one-off checks.
You want **always-on monitoring, fast alerts, and a bot-friendly control surface**.

## Buy ClawGuard Pro - it's only $8
**https://clawguard.net**

Every release should be verified before install. See `Verify Downloads` below.

---

## Why Pro
ClawGuard Pro gives your OpenClaw setup what production systems need:

- 24/7 daemon monitoring (not on-demand snapshots)
- Live local dashboard
- Historical metrics + trend analysis
- Proactive alerts when things start drifting
- Rich OpenClaw-oriented endpoints and integrations

If your bot has meaningful access to your machine, Pro is the version that helps you keep that machine safe and stable.

## What You Get With Pro
- Always-on CPU, memory, disk, network monitoring
- Alerting and recommendations
- Better operational visibility for autonomous bot workflows
- Built for low overhead, designed to stay out of the way

Get access at:
**https://clawguard.net**

---

## Free Lite Version (Public Repo)
This repository is intentionally **Lite-only**.

Included here:
- `skill/clawguard-lite/SKILL.md`
- `skill/clawguard-lite/snapshot.py`
- `scripts/release/sign_release.sh`
- `scripts/release/verify_release.sh`
- `SECURITY.md`

Lite is useful for quick, one-shot checks, but it is not the full product.

### Run Lite
```bash
python3 skill/clawguard-lite/snapshot.py
```

### Lite Security Snapshot
`snapshot.py` now includes a `security` block with:
- OpenClaw version posture checks
- Risky gateway config checks (bind/auth)
- Integrity drift checks for key OpenClaw files + installed skills

If you intentionally changed trusted files and want a new baseline:
```bash
CLAWGUARD_LITE_REBASELINE=1 python3 skill/clawguard-lite/snapshot.py
```

## Verify Downloads (SHA-256 + Minisign)
Publisher flow:
```bash
./scripts/release/sign_release.sh dist
```

User verification flow:
```bash
./scripts/release/verify_release.sh dist
```

Optional signing inputs for publishers:
- `MINISIGN_SECRET_KEY=/path/to/minisign.key`
- `MINISIGN_PUBLIC_KEY=/path/to/minisign.pub`

For real deployments, use **ClawGuard Pro**:
**https://clawguard.net**
