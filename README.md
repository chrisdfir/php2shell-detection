# PHP2Shell Detection

Host-side triage and hunting content for indicators associated with
CVE-2026-109618 and CVE-2026-109619, the PHP `session.upload_progress` remote
code execution vulnerabilities. The content inventories PHP versions, collects
session-file and webroot evidence, and hunts process and log artifacts. It is
not a comprehensive exploit detector or a continuous monitoring service.
Findings are investigation leads, not proof of exploitation, and no matches do
not establish that a host is uncompromised.

Author: Chris DiSalle (@chrisdfir)

## Contents

| File | Purpose |
|---|---|
| `Generic.Detection.PHP2Shell.yaml` | Velociraptor artifact with six sources: process behavior, access logs, error logs, session files, webroot files, and PHP installations |
| `PHP2Shell-Check.ps1` | Standalone Windows scan: session files, webroot, version inventory, known-good diff |
| `PHP2Shell-Check.sh` | Linux counterpart of the PowerShell checker; JSON report on stdout |
| `POST-COMPROMISE.md` | Ordered investigation guide for a known-compromised host |
| `SUPPORTED.md` | Supported, partial, and unsupported environments and telemetry |
| `VALIDATION-METHOD.md` | Validation scope, results, evidence, and known limits |
| `CHANGELOG.md` | Release history |

## Quick start

Velociraptor:

```text
velociraptor --definitions . artifacts collect Generic.Detection.PHP2Shell --output out.zip
```

Set `SessionPaths`, `WebRoots`, and `AccessLogGlobs` for the deployment. Use
comma-separated values. `SinceDate` controls the low-scoring file modification
window; blank uses the last seven days.

PowerShell:

```powershell
.\PHP2Shell-Check.ps1 -SessionPaths @('C:\custom\sessions') -WebRoots @('D:\www')
.\PHP2Shell-Check.ps1 -WebRoots C:\inetpub\wwwroot -DiffAgainst C:\clean-copy
```

Linux:

```bash
./PHP2Shell-Check.sh -p /var/lib/php/sessions -w /var/www/html
./PHP2Shell-Check.sh -w /var/www/html -d /clean-copy-of-webroot
```

Both checkers accept `-b` / `-PhpBins` to pin PHP binaries. The bash checker
accepts `-f` to override the fixed-version mapping.

## Sources and signals

- **ProcessBehavior**: immediate children of PHP and web-server processes,
  classified against a shell/tool allowlist. A snapshot only; short-lived
  children can be missed. `FilterToToolAllowlist=Y` restricts output.
- **AccessLogEvidence**: log lines containing `php2shell` or
  `PHP_SESSION_UPLOAD_PROGRESS`. The method is not restricted, because PHP 8.4
  can parse multipart input on non-POST methods. These are literal markers;
  ordinary access logs usually omit request bodies.
- **FpmErrorLogEvidence**: `Allowed memory size ... exhausted` and
  `Session object destruction failed` lines from PHP/FPM error logs. Rows carry
  `IsMemoryExhaustion`, `IsSessionDestructionFailure`, and
  `HasUnknownLineZero`. Both patterns are nonspecific; judge density and
  timestamps. OOM is common but not a mandatory footprint of every attack path.
- **SessionFileEvidence**: `sess_*` files containing `upload_progress_` plus a
  PHP opener (`<?php`, case-insensitive, or `<?=`) or a serialized-object
  marker (`O:` / `C:`, including nested and pipeless forms). Co-occurrence is
  suspicious, not proof of execution.
- **RecentPhpFiles**: `.php` files scoring at least two of eight pattern
  families, or modified inside the window. The score counts families, not
  probability. The pair `request_input` plus `callback_vectors` alone is
  demoted to WEAK based on WordPress core calibration; other pairs can still be
  legitimate application code.
- **PHPInstallations**: discovered runtimes, each probed with `php -n -v` under
  a hard `MaxProbes` budget. Only a zero-exit probe can issue a verdict. A
  version read from a directory name is an unverified `PathHint`.

## Exit codes

The checkers use the same exit semantics. The Velociraptor artifact emits rows
and has no package-wide exit code.

| Code | Meaning |
|---|---|
| 0 | No session-content finding, no STRONG webroot finding (score >= 2 excluding the exact `request_input` + `callback_vectors` pair), and no version below the fixed threshold. Weak findings may still be present |
| 1 | Session-content finding, STRONG webroot finding, and/or a PHP version below the fixed threshold |
| 2 | Assessment incomplete with no threshold match: scan errors, no existing directory scanned, or an undetermined PHP version |

A threshold match takes precedence over scan errors. An undetermined version is
a coverage gap, so it maps to 2, never to 1 on its own. Diff findings never
change the exit code.

## Version verdicts and advisory status

Versions are compared numerically, component by component. A string comparison
would misjudge 8.3.9 as patched against 8.3.36.

The official fixed thresholds, confirmed against php.net and the php-src GHSAs
on 2026-10-21, are 8.2.35, 8.3.36, 8.4.27, and 8.5.12. A verdict applies only
to CVE-2026-109618 and CVE-2026-109619. It does not assess other PHP
vulnerabilities or prior compromise.

Three caveats matter when interpreting an at-or-above-threshold version result:

- **CVE-2026-115560** (php.net informational advisory, 2026-10-23) is not yet
  patched. It requires upload progress enabled, a configured `php_binary` or
  `php_serialize` handler, and an application switch to `php` via `ini_set()`
  before `session_start()`. PHP recommends `session.upload_progress.enabled=0`
  until the next bugfix release; applications that never switch handlers at
  runtime may keep it enabled.
- **php-src PR 22113** (session fixation via a form-supplied session ID, and
  the serializer leak) is open, not merged into these releases.
- **Chain A** (upload-progress filename stored in a session file, then included
  through an application LFI) is reported to work on patched PHP. Session-file
  evidence remains relevant on a patched host.

Distributions often backport fixes without changing the upstream version.
Confirm a below-threshold verdict against the package changelog:

```bash
apt changelog php8.3-fpm | grep -E '109618|109619'
rpm -q --changelog php-fpm | grep -E '109618|109619'
```

The Velociraptor artifact rejects malformed and branch-mismatched mapping
values and surfaces the configured value as `ConfiguredFixedVersion`. The
standalone checkers also treat a wrong-branch mapping as a coverage gap, but
their override parsing is less strict than the artifact; verify overrides by
hand. Over budget, nothing executes and every candidate reports `budget
exceeded - unverified`.

## Coverage limits

- Default paths are not complete discovery. Adjust them per deployment.
- Velociraptor reads at most 1 MB per session file and 500 KB per PHP file.
  The PowerShell checker reads whole files.
- Access logs usually omit request bodies, so body markers can be invisible.
- Compressed logs are skipped. Access and error log output is capped at 10000
  rows, and one chatty log can crowd out others in the same collection.
- Session directories are scanned non-recursively; configure each leaf
  directory of a nested `session.save_path`.
- Process results are a snapshot, not a history.
- Neither checker decodes obfuscation or parses PHP syntax. Only `.php` files
  are scored in the webroot hunt.
- Response-side indicators such as an anomalous `PHPSESSID` cookie require
  local response-header logs and are documented in `POST-COMPROMISE.md`; no
  default threshold is shipped.
- Container-internal PHP, macOS, FreeBSD, and real cPanel/Plesk/Remi layouts
  are outside validated coverage. `AdditionalBinaryGlobs` extends artifact
  binary discovery only; it does not discover application roots, session
  stores, logs, or container namespaces, and it does not establish support
  for an unvalidated platform.
- The bash checker's guaranteed-valid JSON assumes `iconv` is installed.

## Validation

The content was evaluated three complementary ways: platform regression
suites against stubbed fixtures, an isolated AWS A/B matrix (8.3.35 versus
8.3.36 across Apache/FPM and cleanup settings), and eleven rounds of
independent adversarial review. The final review assessment was SOLID within
the reviewed scope. That assessment covers detection logic and documentation;
it is not evidence of fleet-scale performance, field precision, or
comprehensive detection recall.

Supervised incident-response triage is supported now. Fleet-wide continuous
hunting is not yet production-validated: the collection contract, measured
resource budgets, holdout false-positive calibration, and a multi-host pilot
are still in progress. See `SUPPORTED.md` for the environment matrix and
`VALIDATION-METHOD.md` for evidence and limits.

## References

- [php.net security archive](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [php-src PR 22113](https://github.com/php/php-src/pull/22113)
- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)
- [Generic.Applications.PHPInventory](https://docs.velociraptor.app/exchange/artifacts/pages/phpinventory/)
