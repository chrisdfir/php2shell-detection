# Changelog

## v1.2.0 (2026-10-24)

### Detection

- Standalone checkers reject a fixed-version mapping from the wrong branch,
  matching the artifact.
- A missing or non-executable pinned PHP binary is a coverage gap (exit 2).
- Web-root diff traversal and hash failures are recorded in `ScanErrors`.
- `AccessLogEvidence` exposes `PossiblyTruncated`. `SessionFileEvidence`
  and `RecentPhpFiles` expose `ReadTruncated` and `PossiblyTruncated`.

### Documentation

- Added `SUPPORTED.md` with supported, partial, and unsupported environments
  and telemetry prerequisites.
- Scoped production claims in README and VALIDATION-METHOD.
- Corrected baseline-diff and `APP_KEY` retention wording in
  POST-COMPROMISE.md.

### Validation

- bash: 32 passed, 0 failed, 3 explicit chmod skips.
- PowerShell: 38 passed, 0 failed, 1 YAML-module skip.

## v1.1.0 (2026-10-24)

### Detection

- `AccessLogEvidence` no longer requires POST. PHP 8.4 can parse multipart
  input on GET, PUT, PATCH, and DELETE.
- `FpmErrorLogEvidence` also matches `Session object destruction failed` and
  classifies rows with `IsMemoryExhaustion`, `IsSessionDestructionFailure`,
  and `HasUnknownLineZero`.
- Session-content detection recognizes the `<?=` opener in the artifact, the
  bash checker, and the PowerShell checker.
- Version verdicts are explicitly scoped to CVE-2026-109618 and
  CVE-2026-109619. Thresholds and exit semantics are unchanged.

### Documentation

- README rewritten for concision and current advisory context.
- Added CVE-2026-115560, open php-src PR 22113, and the patched-host Chain A
  caveat.
- POST-COMPROMISE.md corrected: OOM is a common but not mandatory footprint,
  and configuration checks cover CVE-2026-115560 preconditions.
- VALIDATION-METHOD.md records the 2026-10-24 coverage update and new
  artifact hash.

### Validation

- bash: 30 passed, 0 failed, 3 explicit chmod skips (Windows runner).
- PowerShell: 36 passed, 0 failed, 1 YAML-module skip.
- AWS workbench: artifact verify rc=0; focused collection 12/12 checks.

## v1.0.0 (2026-10-22)

- Initial public release of the Velociraptor artifact, bash and PowerShell
  checkers, post-compromise guide, and validation method.
- Validated with platform regression suites, an isolated AWS A/B matrix, and
  eleven rounds of independent adversarial review.
