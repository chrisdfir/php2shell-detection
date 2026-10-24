# Changelog

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

## v1.0.0 (2026-10-22)

- Initial public release of the Velociraptor artifact, bash and PowerShell
  checkers, post-compromise guide, and validation method.
- Validated with platform regression suites, an isolated AWS A/B matrix, and
  eleven rounds of independent adversarial review.
