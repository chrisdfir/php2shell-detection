# Supported environments

This file defines what the detection content was tested against and what it
only partially covers. Anything not listed as supported is a review lead, not
a coverage guarantee.

## Platforms and collectors

| Area | Supported | Partial | Unsupported |
|---|---|---|---|
| Collector | Velociraptor 0.77.3 on Linux and Windows | Other Velociraptor 0.7x releases | Server-side scheduled hunting at fleet scale |
| Standalone | `PHP2Shell-Check.sh` on Linux; `PHP2Shell-Check.ps1` on PowerShell 7 | PowerShell 5.1 | The bash checker on Windows without GNU tools and `iconv` |
| Host OS | Linux with glibc; Windows Server 2016 and later | Windows 10/11 workstations | macOS and FreeBSD validated coverage |
| Container | Collector running inside the container | Collector running on the host and reading mounted container filesystems | Container-internal PHP discovered from the host |

## PHP runtime and SAPI

| Area | Supported | Partial | Unsupported |
|---|---|---|---|
| SAPI | Apache `mod_php`, PHP-FPM, `php-cgi` | LiteSpeed (`lsphp`), FrankenPHP, IIS FastCGI | SAPIs not visible in process or log telemetry |
| Discovery | PATH plus common Linux layouts (`/usr`, `/usr/local`, Remi, Plesk, cPanel, CloudLinux, LAMPP, Bitnami) and Windows layouts (`C:\php*`, Program Files, Plesk, Laragon, WAMP, XAMPP, IIS) | Custom prefixes via `AdditionalBinaryGlobs` | Application roots, session stores, and logs outside configured paths |
| Version probe | `php -n -v` under `MaxProbes` | Discovery-only mode (`EnableProbing=N`) | A probe timeout inside VQL; collection-level limits apply |
| Verdict scope | CVE-2026-109618 and CVE-2026-109619 thresholds | Distro backports that do not bump the upstream version | CVE-2026-115560 and other PHP vulnerabilities |

## Session storage

| Area | Supported | Partial | Unsupported |
|---|---|---|---|
| Backend | Flat files named `sess_*` in each configured directory | Nested `session.save_path` moduli, one leaf directory per parameter | Redis, Memcached, database, and other non-file handlers |
| Content | `upload_progress_` plus a PHP opener or serialized object | Custom progress prefixes; files larger than 1 MB (flagged `ReadTruncated`) | Obfuscated or encrypted session content |
| Cleanup | Files still present at collection time | Files removed by `session.upload_progress.cleanup` before collection | Memory-only session state |

## Logs

| Area | Supported | Partial | Unsupported |
|---|---|---|---|
| Access logs | Plain-text lines containing a literal marker | Rotation and multiple globs; IIS log format | Request bodies omitted by the server; compressed files |
| Error logs | `Allowed memory size ... exhausted` and `Session object destruction failed` | Multiple globs and rotation | Compressed files, journald, container stdout, centralized log stores |
| Response evidence | Not collected by default | Local response-header logs for `PHPSESSID` cookie review | A universal cookie-length threshold |

## Web root

| Area | Supported | Partial | Unsupported |
|---|---|---|---|
| Files | `.php` files under configured roots | Symlinks and junctions; deep trees (artifact bare `**` recursion is depth-limited) | Other executable extensions; PHP embedded outside `.php` files |
| Content | First 500 KB per file; lexical pattern families | Files larger than 500 KB (flagged `ReadTruncated`) | Obfuscation, encoding, and runtime-generated code |
| Baseline | Known-good directory diff | Deployment-matched baseline with documented drift | Memory-only changes and changes outside the compared tree |

## Telemetry prerequisites

- Readable session, webroot, and log paths.
- Permissions sufficient for the collector account.
- UTC time synchronization across hosts and log sources.
- Log retention covering the investigation window.
- Process visibility for live triage; historical EDR or auditd data for short-lived children.
- An accurate mapping from installed binaries to the runtime actually serving requests.
- GNU tooling and `iconv` for guaranteed-valid bash JSON.
- Velociraptor 0.77.3 for the validated artifact behavior.

## Reporting

Every capped source exposes truncation state:

- `AccessLogEvidence`: `PossiblyTruncated` when matches exceed 10,000 rows.
- `FpmErrorLogEvidence`: `PossiblyTruncated` when matches exceed 10,000 rows.
- `SessionFileEvidence`: `ReadTruncated` for files over 1 MB; `PossiblyTruncated` over 10,000 rows.
- `RecentPhpFiles`: `ReadTruncated` for files over 500 KB; `PossiblyTruncated` over 10,000 rows.

Standalone checkers report `ScannedDirectories`, `MissingDirectories`, and
`ScanErrors`. A missing or non-executable pinned PHP binary, a wrong-branch
fixed-version mapping, and a diff hash or traversal failure are coverage gaps
and drive exit code 2.
