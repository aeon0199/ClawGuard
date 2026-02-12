# Security Notes

This public repo contains **ClawGuard Lite** only.

## What Lite Checks Today

`skill/clawguard-lite/snapshot.py` includes a `security` section with:

- OpenClaw version posture against minimum safe/recommended versions
- Risky local OpenClaw gateway config checks (bind/auth)
- Basic permissions checks for sensitive config
- Integrity drift checks for selected OpenClaw files and installed skills

## Integrity Baseline

On first run, Lite writes:

- `~/.clawguard-lite/integrity-baseline.json`

Use this baseline to detect unexpected local changes in later runs.

If you intentionally changed OpenClaw skills/config and want to refresh baseline:

```bash
CLAWGUARD_LITE_REBASELINE=1 python3 skill/clawguard-lite/snapshot.py
```

## Verifying Release Files

Use the included scripts:

```bash
# publisher side
./scripts/release/sign_release.sh dist

# user side
./scripts/release/verify_release.sh dist
```

If `MINISIGN_SECRET_KEY` is set during signing, the script also generates
`SHA256SUMS.minisig` and can bundle `minisign.pub` (via `MINISIGN_PUBLIC_KEY`).

## Reporting Security Issues

Please report issues privately first: `security@clawguard.net`

