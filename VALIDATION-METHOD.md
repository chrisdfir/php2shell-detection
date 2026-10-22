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

Final state: bash 32/32 passed; PowerShell 30 passed, 0 failed (one
environment-dependent YAML-parse check reports an explicit skip when no
parser module is installed).

## 4. False-positive calibration (WordPress core baseline)

The webroot scoring was calibrated against a real codebase: wordpress.org
latest (1,512 PHP files) scored by the artifact on AWS. Before calibration,
66 files (4.4%) reported STRONG, 74% of them the single pair
request_input+callback_vectors - idiomatic CMS code, not shell indicators.
After calibration (that exact pair alone demotes to WEAK; the classic
eval($_POST[...]) shell keeps STRONG via eval,request_input), WordPress core
yields 17 STRONG rows (1.1%). The rule, its rationale, and the Signal column
are identical in both checkers and the artifact; the demoted rows are still
reported, just not exit-code-driving.

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

Real-request/log validation (2026-10-22): the public proof-of-concept lab
(ikow/php2shell-poc: PHP-FPM 8.2.35 behind nginx, Apache mod_php 8.2.35 with
a 32M memory limit) was driven with genuine exploit-shaped requests. This is
request-and-log validation, not exploit reproduction: the builds used are
themselves patched (8.2.35), and the memory exhaustion is nonspecific, so
nothing here demonstrates successful exploitation of the CVEs. What it does
establish: the Apache chain produced the documented worker-crash signature,
the FPM chain produced a genuine `Allowed memory size ... exhausted` fatal
written by the real FPM worker to its configured error-log file, and a
`Generic.Detection.PHP2Shell/FpmErrorLogEvidence` collection over that file
returned exactly that line with `PossiblyTruncated=false`. A 10001-match
fixture confirmed the cap semantics: exactly 10000 rows returned with
`PossiblyTruncated=true`. The Windows host additionally passed a 16-check
matrix covering every source, the probe budget (threshold, over-budget,
discovery-only), and path-hint extraction on versioned Windows layouts.

### Final artifact record

The submitted artifact is `Generic.Detection.PHP2Shell.yaml` at commit
`b8aab48`, SHA-256
`685A8AA77CD621FCCEEBEB5BAC63E2B402F79B2CFCF168FD79EA944661583266`
(byte-identical to the tree at commit `3869633`; `b8aab48` changed only
this document). All results below were produced against exactly this file:

- Linux matrix, AWS AL2023 workbench (SSM only), Velociraptor 0.77.3:
  35/35 checks - negatives, malformed inputs, session-marker splits, log
  rotation/gz/cap, probe budget at the exact threshold (MaxProbes=124
  against 123 candidates), over-budget (MaxProbes=2), default-budget
  over-budget, nonzero-exit no-verdict, branch-mismatched fixed values.
- Windows Server 2022 (SSM only), Velociraptor 0.77.3: 16/16 checks -
  every source, budget and discovery-only modes, PathHint extraction, no
  PATH probe on Windows; plus the live ProcessCreatedAfter assertions
  (past cutoff reports a real php.exe parent/child pair, future cutoff
  returns zero rows, MatchesToolAllowlist classification present).
- A/B end-to-end (ephemeral instance, 8 containers: 8.3.35/8.3.36 x
  apache/fpm x cleanup on/off): the artifact collected inside every
  container - 32/32 checks (version verdicts, webshell differentiation,
  session evidence per cleanup flag, real OOM fatals from every
  container's own error log); results in `results/ab-final-report.txt`
  in the evidence bucket. The bash checker ran the same matrix:
  10/10 expected-vs-actual (`results/validation-report.txt`).
- Live Windows checker run: `PHP2Shell-Check.ps1` against the real host
  PHP 8.3.35 exits 1 with "below official fixed version 8.3.36" for
  both discovered binaries. This live run caught a discovery gap (the
  shallow `C:\php*\php.exe` pattern misses the standard versioned
  subdirectory layout `C:\php\<version>\php.exe`); fixed and covered by
  a suite check.
- Regression suites: bash 32/32; PowerShell 34 passed, 1 explicit
  environmental skip (YAML-parse check without a parser module; the
  artifact is parsed by the bash suite and by `velociraptor artifacts
  verify` on every run).
- Evidence: `s3://php2shell-evidence-d63bfbc3bcb9ee837200948705/` under
  `2026-10-22/7cddbcb/` (development-round collections) and
  `2026-10-22/3869633/` (final-round collections including the real FPM
  error log, the truncation-test collection, and the artifact hash).
  `7cddbcb` and `3869633` are successive commits of the same campaign;
  the final-round prefix holds the evidence for the hash above.

## 3. Independent adversarial review

The checkers, the artifact, and the validation claims themselves were
reviewed over eleven iterative rounds by an independent reviewer with
read-only access, with each round's findings fixed or rebutted with
measurements before the next round. The severity curve converged
(high → medium → low → documentation nits) and the final verdicts were
**SOLID** for both the detection logic and the validation claims, with no
high-severity findings outstanding.

## 5. Run manifest and evidence

Full-collection outputs and command logs are retained in the encrypted
evidence bucket `php2shell-evidence-d63bfbc3bcb9ee837200948705`, keyed by
date and artifact commit (for example `2026-10-22/7cddbcb/`), with the
following recorded per run: instance IDs, AMI, Velociraptor version,
artifact SHA-256, parameters, runtime, and row counts. The instance role
has `PutObject` only; retrieval is operator-side. S3 versioning keeps
prior object versions; version IDs and SHA-256 hashes for each object are
recorded in a manifest stored alongside the evidence.

Reproduce any artifact collection with:

```
velociraptor --definitions <dir> artifacts collect \
  Generic.Detection.PHP2Shell/<Source> --args "Param=Value" --output out.zip
```

Lint with `velociraptor artifacts verify Generic.Detection.PHP2Shell.yaml -v`.
The regression suites run offline: `bash tests/run-tests.sh` and
`pwsh tests/run-tests.ps1` (one environment-dependent YAML-parse check
reports an explicit skip when no parser module is installed).

## Known limitations

See **Interpretation and coverage** in the README. The most operationally
relevant: defaults are not complete discovery (adjust paths per deployment);
the version inventory is a lead to review against the official php.net
advisory, not a vendor verdict; path-derived versions trust the directory
name and never issue verdicts on their own; distro packages may backport
the fix without bumping the upstream version (confirm via package
changelog); artifact content reads are capped (1 MB per session file,
500 KB per PHP file); error-log and access-log scans skip compressed
files and cap output at 10000 lines, so one very chatty log can crowd out
other files in the same collection, and the cap does not bound bytes
scanned (a very large log with few matches is read in full); the version
probe runs `php -n -v` with no per-process timeout (VQL execve offers
none - collection-level resource limits apply, and a hanging binary would
stall the probe step); and the bash checker's guaranteed-valid JSON output
assumes `iconv` is installed. The known-good webroot diff and
POST-COMPROMISE.md were added after the lab validation and are covered by
the regression suites only. Container-internal PHP runtimes, macOS and
FreeBSD hosts, and real cPanel/Plesk/Remi servers are outside validated
coverage; the `AdditionalBinaryGlobs` parameter exists for such layouts.
