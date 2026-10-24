# If you are compromised: finding web shells

You know or strongly suspect an attacker got in. They had time, so assume
more than one web shell, assume modified legitimate files, and assume the
same trick was used on more than one server. Work in this order; it goes
from most reliable to least.

## 1. Compare against a known-good copy

This finds more than any scan, because it does not depend on recognizing
the shell at all.

- Rebuild the application from a trusted source (CI artifact, git tag,
  vendor package) into a separate folder. Diff it against the live web
  root. Extra, missing, and changed files are your suspect list.
- On packaged files, use `rpm -Va` or `dpkg -V` to spot tampering.
- Anything in the web root you cannot account for is suspect.

Both checkers in this repo do this step for you:

```bash
./PHP2Shell-Check.sh -w /var/www/html -d /clean-copy-of-webroot
```

```powershell
.\PHP2Shell-Check.ps1 -WebRoots C:\inetpub\wwwroot -DiffAgainst C:\clean-copy
```

Added and modified files are the suspects. Deleted files can mean the
attacker cleaned up. The diff never changes the exit code; read it as
evidence, then confirm hits by hand.

## 2. Look at what ran, not just what exists

A web shell has to execute, and execution leaves traces that content
scans cannot fake.

- Process history: a web server or PHP-FPM worker starting shells,
  Python, curl, certutil, or bitsadmin. This is the single most
  reliable sign. Use EDR or auditd history if you have it.
- Access logs: POST requests to paths that do not exist in the clean
  copy, requests with unusual parameter counts, or very long URLs.
- Network: outbound connections made by web worker processes during
  the compromise window.
- Exploit signals published by the PHP researchers (Wiz) and the
  php-src advisory, worth grepping for directly:
  - multipart requests followed by memory-limit errors or bursts of
    HTTP 500 responses from the same source; on PHP 8.4 and later the
    multipart input can arrive on GET, PUT, PATCH, or DELETE as well
    as POST;
  - `Session object destruction failed` in PHP or FPM error logs,
    which can accompany session-store cleanup after a fatal error;
  - unexpectedly large or malformed `PHPSESSID` response cookies
    (the memory-disclosure primitive leaks worker memory through
    that cookie);
  - unexplained PHP worker churn (FPM children exiting or being
    respawned);
  - `Maximum execution time exceeded` and fatal or parse errors on
    attacker-reachable routes;
  - oversized multipart filenames or `PHP_SESSION_UPLOAD_PROGRESS`
    fields in POST bodies (the shape of the public proof-of-concept).

Exploit attempts were observed from disclosure day (Cloudflare reported
attack traffic and payload mutation against customers), so treat
scanning as ongoing, not hypothetical. Do not judge risk by public
exploit quality: the circulating proof-of-concept is unreliable and, in
its author's own correction, memory-safety only rather than code
execution, while the researcher chains behind the advisories achieve
full unauthenticated RCE.

## 3. Scan file contents

Score files on combinations of code-execution patterns (eval or assert
plus request input plus callbacks or decoders), not single keywords.
Single keywords match half the plugins in a typical CMS. Both checkers
do this; expect false positives and confirm each hit by hand.

Two honest limits: heavily obfuscated shells can pass a regex scan, and
a scan alone cannot tell you when the shell ran. That is what steps 1
and 2 are for.

## 4. Check the places that persist and do not look like shell files

- Session files: serialized objects or PHP tags inside `sess_*` files,
  especially with `upload_progress_` entries (both checkers scan these).
- `.user.ini`, `.htaccess`, `auto_prepend_file`, `auto_append_file`:
  these run on every request without any shell file existing.
- PHP-FPM pool settings and per-request `PHP_VALUE` overrides.
- Upload temp folders and every level of `session.save_path`.
- PHP-FPM and web-server error logs: several php2shell paths are
  reached through a fatal error. `Allowed memory size ... exhausted`
  during multipart parsing is the common OOM signature, and
  `Session object destruction failed` can follow a fatal during
  session cleanup. A burst of either around the exploitation window is
  consistent with the trigger (the artifact's `FpmErrorLogEvidence`
  source scans both; a handful is normal on busy apps, judge density
  and timestamps). OOM is not a mandatory footprint of every path.
  On PHP-FPM, a startup-phase fatal also kills the worker, so clusters
  of worker exit/restart messages deserve a look.
- PHP configuration: `session.upload_progress.enabled`, the
  configured `session.serialize_handler`, `memory_limit`,
  `fatal_error_backtraces` (PHP 8.5), and OPcache settings. A runtime
  switch from `php_binary` or `php_serialize` to `php` before
  `session_start()` is the precondition for CVE-2026-115560.

## 5. Assume the same trick worked elsewhere

The php2shell advisories (CVE-2026-109618 / CVE-2026-109619) make the
general point: the attacker's requests land on the same worker, and one
confirmed shell means the whole fleet is a candidate. Researchers
demonstrated pre-auth RCE against WordPress, Drupal, Joomla, MediaWiki,
Roundcube, Magento, phpMyAdmin, Nextcloud, Laravel, Symfony and WHMCS;
the flaw is in PHP itself, so any application on a vulnerable runtime
is a candidate. Sweep every PHP host with the same playbook, and while
you have a box, look for second-stage persistence: cron entries,
systemd units, SSH keys, web server config changes.

Two facts worth keeping straight while you do this:

- **Stock configurations are exploitable.** Public exploits work under
  the official `php.ini-production` (`display_errors=Off`,
  `memory_limit=128M`) and reach the bug with chunked multipart requests
  that stay under `post_max_size`. Do not rule a host out because its
  config looks boring.
- **Patched does not mean clear.** The version thresholds cover
  CVE-2026-109618 and CVE-2026-109619 only. Chain A (session injection
  plus an application LFI) is reported to work on patched PHP, the
  session-fixation and serializer fixes in PR 22113 are not merged, and
  CVE-2026-115560 remains unpatched as of 2026-10-24.
- **Version numbers lie on distros.** Debian, Ubuntu and RHEL often
  backport the fix without bumping the upstream version, so a build
  reporting a pre-fix number may be patched. Confirm with the package
  changelog: `apt changelog php8.3-fpm | grep -E '109618|109619'` or
  `rpm -q --changelog php-fpm | grep -E '109618|109619'`.

If the host was exposed during the disclosure window, treat in-memory
secrets as compromised regardless of what the scans find: the memory
disclosure variant of this bug leaves almost nothing on disk. Rotate
`APP_KEY` (keeping the old value in `APP_PREVIOUS_KEYS`), database
credentials, API keys and any TLS keys living on the same box.

## Practical sequence

1. List every PHP host and version (the version inventory in both
   checkers exists for this).
2. Collect web roots, session folders, logs, and process or network
   history.
3. Diff against known-good. That is your suspect list.
4. Content-scan the suspect list, then the full web root.
5. Correlate logs and process history into a timeline.
6. Confirm every hit by hand. Co-occurrence is not execution.
7. Rebuild the host rather than trying to clean it in place.
