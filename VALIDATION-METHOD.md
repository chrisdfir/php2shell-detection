# Validation method

The detection content in this repository was validated in three independent
ways before release. This file describes the method; the repository contains
only the detection content itself.

## 1. Regression suites (detection logic)

Two dependency-free suites (bash and PowerShell) execute the real checkers in
subprocesses, exactly as fleet automation would, against disposable temp
fixtures and stub `php` binaries. Between them they assert, per platform:

- all three exit codes (0 clean / 1 exposure indicator / 2 assessment
  incomplete) and their precedence over one another;
- strong vs weak webroot findings (content score >= 2 vs recent-mtime-only);
- session-content findings, including case-insensitivity of PHP tags versus
  case-sensitivity of `upload_progress_`/serialized-object markers;
- the numeric version comparison (`8.3.9` vs `8.3.36`, the case a string
  comparison gets wrong), leading-zero equality, prerelease and
  four-component rejection, and unmapped-branch semantics;
- probe-failure, scan-error, and traversal-error recording;
- the known-good webroot diff (`--diff-against` / `-DiffAgainst`): added,
  modified, and missing classification, silence on identical trees, a
  nonexistent clean copy rejected with a usage error, and confirmation that
  diff findings never change the exit code;
- structural guards on the Velociraptor artifact (versioned Windows installs
  chained into the result set, numeric `key()` comparison, official
  fixed-version mapping confirmed against the php.net advisory).

Final state: bash 31/31 passed; PowerShell 29 passed, 0 failed (one
environment-dependent YAML-parse check reports an explicit skip when no
parser module is installed).

## 2. Isolated cloud lab (end-to-end A/B matrix)

An isolated AWS environment (SSM Session Manager access only, encrypted
volumes, auto-termination) ran an expected-vs-actual matrix of containerized
PHP targets:

| Dimension | Values |
|---|---|
| PHP version | 8.3.35 (vulnerable, pre-patch) and 8.3.36 (patched, official images) |
| SAPI | Apache (`apache2handler`) and Nginx + PHP-FPM |
| `session.upload_progress.cleanup` | on and off |
| Checker execution | inside each container, against its own PHP binary, session directory, and webroot |

The matrix asserts exit codes, version verdicts, strong/weak signals, and
session-row counts for every container, plus a host-level run (a real
below-fixed PHP on the lab host) and a Velociraptor collection of the
`Generic.Detection.PHP2Shell.yaml` artifact. Final state: **10/10 expected
vs actual assertions passed**: vulnerable hosts flagged, patched hosts
quiet, and patched hosts with session evidence flagged by the session
signal alone (version and session detection are independent).

The matrix exercises the artifact classes the disclosed techniques produce;
it is detection validation, not exploit reproduction.

Windows verification (2026-10-21): the artifact was collected on a live
Windows host with Velociraptor 0.77.3 against portable PHP 8.3.35 laid out in
both supported shapes, a versioned directory and an unversioned probe target.
Both PHPInstallations chains returned the correct below-fixed verdict, the
access-log, session-file, and webroot sources returned the expected rows, and
the artifact passes `velociraptor artifacts verify` cleanly, including the
EXECVE permission declaration its version probes require.

## 3. Independent adversarial review

The checkers, the artifact, and the validation claims themselves were
reviewed over eleven iterative rounds by an independent reviewer with
read-only access, with each round's findings fixed or rebutted with
measurements before the next round. The severity curve converged
(high → medium → low → documentation nits) and the final verdicts were
**SOLID** for both the detection logic and the validation claims, with no
high-severity findings outstanding.

## Known limitations

See **Interpretation and coverage** in the README. The most operationally
relevant: defaults are not complete discovery (adjust paths per deployment);
the version inventory is a lead to review against the official php.net
advisory, not a vendor verdict; path-derived Windows versions trust the
directory name; artifact content reads are capped (1 MB per session file,
500 KB per PHP file); and the bash checker's guaranteed-valid JSON output
assumes `iconv` is installed. The known-good webroot diff and
POST-COMPROMISE.md were added after the lab validation and are covered by
the regression suites only.
