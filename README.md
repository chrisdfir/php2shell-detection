# PHP2Shell Detection

Host-side detection for CVE-2026-109618 / CVE-2026-109619 (the "php2shell" PHP session upload progress RCEs). Unlike the remote version scanners, these tools run on the host: PHP version inventory, session-file evidence, webshell content scoring, a known-good webroot diff, and a Velociraptor artifact for fleet sweeps.

Findings are leads for investigation, not confirmation of exploitation or attribution to a particular vulnerability. No matches do not establish that a host is uncompromised.

**Author:** Chris DiSalle (@chrisdfir)

## Detection content

| File | Coverage |
|---|---|
| `Generic.Detection.PHP2Shell.yaml` | Velociraptor artifact with process, access-log, session-file, and webroot hunts |
| `PHP2Shell-Check.ps1` | Standalone PowerShell session-file and webroot hunts |
| `PHP2Shell-Check.sh` | Linux/bash counterpart of the PowerShell script (PHP version inventory, session-file and webroot hunts, known-good webroot diff) |
| `POST-COMPROMISE.md` | What to look for, in order, when you already know a host was compromised |

The platform regression suites used during validation are retained as validation tooling and described in [VALIDATION-METHOD.md](VALIDATION-METHOD.md); they are not part of this release tree.

The Velociraptor artifact is named `Generic.Detection.PHP2Shell`, following the artifact exchange naming convention.

- **ProcessBehavior:** a snapshot of PHP/web-server processes with children such as shells, interpreters, and downloaders. Legitimate application activity can match; short-lived processes can be missed.
- **AccessLogEvidence:** POST log lines containing `php2shell` or `PHP_SESSION_UPLOAD_PROGRESS`. These are literal markers, not an exploit signature. Standard access logs generally omit request bodies; changed or absent markers evade this hunt.
- **FpmErrorLogEvidence:** `Allowed memory size ... exhausted` fatal errors from PHP-FPM/error logs. The exploit is reached through exactly this fatal error, so a burst of these lines around the exploitation window is the footprint of the trigger itself (a handful is normal on busy apps; judge density and timestamps). Compressed logs (`.gz` etc.) are skipped; decompress copies for deep sweeps. Output is capped at 10000 lines, so one very chatty log can crowd out other files in the same collection.
- **SessionFileEvidence:** `sess_*` files containing `upload_progress_` together with a PHP opening tag (case-insensitive; `<?PHP` is valid PHP) or a serialized-object marker (`O:`/`C:` tokens, including objects nested in arrays and pipeless `php_serialize` output). Co-occurrence does not establish execution; legitimate stored content may match.
- **RecentPhpFiles:** PHP files matching at least two of eight pattern families, or modified within the selected window. The score counts pattern families, not probability of compromise. Comments, examples, and legitimate application code can score highly. Recent modification alone is a weak lead.
- **PHPInstallations:** PHP version inventory with broad filesystem discovery (Linux PATH plus `/usr`, `/usr/local`, Remi, Plesk, cPanel, CloudLinux, LAMPP, Bitnami layouts; Windows `C:\php*`, Program Files x86/x64, Plesk, Laragon, WAMP, XAMPP, IIS layouts - adapted from [Generic.Applications.PHPInventory](https://docs.velociraptor.app/exchange/artifacts/pages/phpinventory/)). Every discovered runtime is probed with `php -n -v` and the **probed version drives any verdict**; a version read from a directory name is reported only as an unverified hint (`PathHint`) and never issues a verdict on its own, and a path/binary disagreement is flagged. Probing is bounded (max 100 binaries per collection) and can be disabled (`EnableProbing=N`) for a discovery-only sweep. Runtime names are allowlisted (`php`, versioned variants, `-cgi`/`-fpm`/`-dbg`; `phpize`/`php-config` are never executed). Versions are compared numerically against the `FixedVersions` parameter. See the advisory-status note below.

## Usage

Import the YAML into Velociraptor, or collect locally:

```text
velociraptor --definitions . artifacts collect Generic.Detection.PHP2Shell --output out.zip
```

Set `SessionPaths` and `WebRoots` to the actual directories in use (comma-separated in Velociraptor). Set `AccessLogGlobs` for custom access-log locations. `SinceDate` controls the low-scoring file modification window; blank defaults to the last seven days. Higher-scoring files are returned regardless of modification time.

For PowerShell:

```powershell
.\PHP2Shell-Check.ps1 -SessionPaths @('C:\custom\sessions') -WebRoots @('D:\www')
# Optional UTC cutoff for the weak modification-time hunt:
.\PHP2Shell-Check.ps1 -SinceDate '2026-10-20T00:00:00Z'
# Optional: pin explicit php binaries for the version inventory (otherwise
# PATH plus common Windows locations are discovered):
.\PHP2Shell-Check.ps1 -PhpBins @('C:\php\8.3.9\php.exe')
# Optional: compare the web root against a clean copy (see POST-COMPROMISE.md):
.\PHP2Shell-Check.ps1 -WebRoots C:\inetpub\wwwroot -DiffAgainst C:\clean-copy
```

For Linux (bash counterpart; human-readable output on stderr, JSON report on
stdout so it can be piped to a file):

```bash
./PHP2Shell-Check.sh -p /var/lib/php/sessions -w /var/www/html
# Optional: pin explicit php binaries for the version inventory (otherwise
# PATH plus common Linux locations are discovered):
./PHP2Shell-Check.sh -b /usr/bin/php,/usr/local/bin/php
# Optional: override the official fixed-version mapping (e.g. for a future advisory):
./PHP2Shell-Check.sh -f '8.3=8.3.36,8.4=8.4.27'
# Optional: compare the web root against a clean copy (see POST-COMPROMISE.md):
./PHP2Shell-Check.sh -w /var/www/html -d /clean-copy-of-webroot
```

The script prints findings and a JSON report including scanned and missing directories and scan errors. A score >= 2 webroot finding drives exit 1 unless the only matched patterns are request_input and callback_vectors - that pair alone is idiomatic CMS code (calibrated against a WordPress core baseline: 74% of benign strong rows), so it reports as a weak lead instead. Exit codes:

| Code | Meaning |
|---|---|
| 0 | No session-content or score >= 2 matches, no version below the official fixed version; weak findings may still be present |
| 1 | Session-content or score >= 2 matches and/or a PHP version below the official fixed version, requiring review |
| 2 | Assessment incomplete with no threshold match: scan errors, no existing directories scanned, or a PHP version that could not be determined |

A threshold match takes precedence over scan errors in the exit code; always inspect `ScanErrors` and coverage. Invalid dates also return 2. An undetermined PHP version is a coverage gap, not exposure evidence, so it maps to 2, never to 1 on its own.

## PHP version inventory and advisory status

The version checks in both detection files compare **numerically**, component-wise. A lexicographic string comparison would misjudge e.g. 8.3.9 (below the fixed version) as patched because `"9" > "3"` as text.

Advisory status, **confirmed against php.net and the php-src GHSAs on 2026-10-21 ~15:10 UTC**: php.net published the security release - **PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 fix two critical unauthenticated-RCE vulnerabilities, CVE-2026-109618 ([OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) and CVE-2026-109619 ([stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))**; see also the [php.net release announcement](https://www.php.net/archive/2026.php). The fixed-version mapping used here (8.2.35, 8.3.36, 8.4.27, 8.5.12) matches the published values exactly, and the checkers label the mapping **official** while still instructing verification against the advisory before acting on any verdict. The version-verdict JSON field is `FixedVersion` in both the checkers and the artifact; its values are the official thresholds. php.net also published minimal source backports for PHP 7.4/8.0/8.1 branches, and notes the risk is highest for mod_php, where an unauthenticated request can trigger the vulnerability before any application code runs. The affected range is widely reported as PHP 5.4 through 8.5.11 (session.upload_progress shipped in 5.4); PHP publishes fixed versions only for supported branches plus the 7.4/8.0/8.1 backports, so the checkers treat any branch without a mapping as **manual review** rather than clearing it.

**Distro backports:** Debian, Ubuntu and RHEL often ship the security fix as a patch without bumping the upstream version, so a build reporting 8.3.35 (or similar) may already be fixed. A below-fixed verdict on a distro PHP must be confirmed against the package changelog before acting: `apt changelog php8.3-fpm | grep -E '109618|109619'` or `rpm -q --changelog php-fpm | grep -E '109618|109619'`.

## Interpretation and coverage

Paths are defaults, not complete discovery. Adjust them for each deployment and use sufficient read permissions. The PowerShell script does not collect process or access-log evidence. Review Velociraptor collection errors separately from result rows.

The Velociraptor file-content checks read at most 1 MB per session file and 500 KB per PHP file; later content can be missed. The PowerShell checks read the whole file. Neither decodes obfuscation nor parses PHP syntax. Only `.php` files are included in the webroot hunt. Compressed logs are excluded. Deleted files, expired logs, and activity outside the collected paths are not covered. Session content and log lines may contain sensitive data; handle collection results accordingly.

Session directories are scanned non-recursively: only top-level `sess_*` files in each configured directory are examined (matching PHP's default flat `session.save_path` layout). Nested directory structures such as PHP's `N`-level `session.save_path` moduli (`/tmp/sessions/N/sess_...`) are not traversed; configure each leaf directory explicitly.

Additional known limitations in the bash checker: guaranteed-valid JSON output requires `iconv` (absent → invalid-UTF-8 filenames can produce invalid JSON); `--fixed-versions` override major components are not bounds-checked (an explicitly malformed override can wrap comparison arithmetic); a recently-modified **empty** `.php` file is reported by the bash checker but omitted by the PowerShell one (parity gap, thresholds unaffected).

## Validation

The detections were validated three ways before release: platform regression
suites running the real checkers against stubbed fixtures, an isolated cloud
lab A/B matrix (vulnerable 8.3.35 vs patched 8.3.36 across Apache/FPM and
session-cleanup settings, 10/10 expected-vs-actual assertions), and eleven
rounds of independent adversarial review converging on a SOLID verdict for
both the detection logic and the validation claims. The method, scope, and
final results are described in **[VALIDATION-METHOD.md](VALIDATION-METHOD.md)**.
