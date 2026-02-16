# Security Notes

ClawGuard includes security posture checks and release verification tooling.

## Runtime Security Checks

`GET /api/security` reports:

- OpenClaw version posture (required/recommended minimums)
- OpenClaw gateway/config risk findings (bind/auth + file permissions)
- Integrity drift checks for key OpenClaw files and installed skills
- Actionable recommendations for bots/users

`GET /api/containment` reports:

- containment mode and policy state (enabled/shadow/enforced)
- recent containment actions and outcomes

HTTP/API safety defaults:
- hard monitor-only mode available via `mode = readonly` (disables containment execution)
- loopback bind by default (`http_bind = 127.0.0.1`)
- non-loopback bind is blocked unless `allow_remote_http = true`
- remote API use requires `api_auth_token` (`Authorization: Bearer` or `X-API-Key`)
- API rate limiting is enabled by default (`api_rate_limit_per_min`)
- dashboard responses include a restrictive CSP header
- wildcard CORS is not enabled

## Integrity Baseline

Baseline file (default):

- `~/.clawguard/integrity-baseline.txt`

To intentionally refresh the baseline:

```bash
CLAWGUARD_REBASELINE=1 ./clawguard
```

## Verifying Release Files

Use included scripts:

```bash
# publisher side
./scripts/release/sign_release.sh dist

# user side
./scripts/release/verify_release.sh dist
```

Release signing is mandatory:
- set `MINISIGN_SECRET_KEY=/path/to/minisign.key`
- set `MINISIGN_PUBLIC_KEY=/path/to/minisign.pub`
- set `CLAWGUARD_PUBLISHER_ID=<stable-publisher-id>`
- `sign_release.sh` emits `SHA256SUMS`, `SHA256SUMS.minisig`, and `minisign.pub`
- `sign_release.sh` also emits `RELEASE_PROVENANCE.txt` (publisher + commit + build metadata)

Optional stricter verify on user side:
```bash
CLAWGUARD_EXPECTED_PUBLISHER_ID=<stable-publisher-id> ./scripts/release/verify_release.sh dist
```

## macOS Provenance

Publisher helpers:
- `scripts/release/macos_sign_and_notarize.sh`

User verification helper:
- `scripts/release/macos_verify_provenance.sh`

## Private Reporting

Report vulnerabilities privately first: `security@clawguard.net`
