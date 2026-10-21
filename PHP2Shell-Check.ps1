<#
.SYNOPSIS
    PHP2Shell community detection content - session-file and webroot artifact scan.

.DESCRIPTION
    Standalone triage for admins - no Velociraptor required. This is community
    detection content: it looks for artifacts and inventories PHP versions.
    Checks:
      0. PHP installations and versions, compared NUMERICALLY against a
         official fixed-version mapping (confirmed 2026-10-21; still a lead
         to review, not a vendor verdict - see README "PHP version inventory")
      1. Session files containing PHP tags or serialized objects
         (suspicious-content scan; indicators for review, not proof of exploitation)
      2. .php files in web roots scored on webshell-indicator CONTENT, with a
         recent-mtime window as a secondary heuristic signal

    Exit codes: 0 = no findings met any threshold and nothing was left
    unassessed. This is NOT a statement that the host is safe or
    uncompromised - absence of indicators is not absence of compromise.
                1 = suspicious session-file content and/or strong webshell
    content findings and/or a PHP version below the official fixed version
    (see output for details).
                2 = assessment incomplete with no threshold match: scan errors,
    no existing directories scanned, or a PHP version that could not be
    determined. An undetermined version is a coverage gap, NOT exposure
    evidence, so it never surfaces as exit code 1 on its own.

    Weak (mtime-only) webroot findings are heuristic and always require manual
    review; they do not by themselves set exit code 1.

.NOTES
    Author: Chris DiSalle (chrisdfir)
    Run with: powershell -ExecutionPolicy Bypass -File .\PHP2Shell-Check.ps1 [-Verbose]
#>
[CmdletBinding()]
param(
    [string[]]$SessionPaths = @("$env:TEMP", 'C:\Windows\Temp', 'C:\temp', 'C:\inetpub\temp'),
    [string[]]$WebRoots = @('C:\inetpub\wwwroot', 'C:\xampp\htdocs'),
    # Optional. When omitted, a rolling 7-day window ending now is used.
    [string]$SinceDate,
    # Optional explicit php executable paths to inventory. When omitted, PATH
    # and common Windows install locations are discovered. Exists so fleet
    # wrappers and tests can pin exact binaries.
    [string[]]$PhpBins = @(),
    # Official first-fixed-version per branch, confirmed against the php.net
    # advisory and php-src GHSA advisories (2026-10-21). Re-verify against
    # future advisories before acting on any verdict (see README). Caller
    # entries MERGE over these defaults (bash parity) and must be exactly
    # N.N.N - a partial or four-component value would misclassify a branch.
    [hashtable]$FixedVersions = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' },
    # Optional clean copy of the web root. When set, every file in each web
    # root is compared against this tree: added or changed files are the
    # suspect list, deleted files may be attacker cleanup. Evidence for the
    # analyst: the diff never changes the exit code.
    [string]$DiffAgainst = ''
)

$defaultFixedVersions = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
# Merge caller entries over defaults (bash parity). Hashtable + hashtable
# throws on duplicate keys, so clone-and-assign instead.
$mergedFixed = $defaultFixedVersions.Clone()
foreach ($k in @($FixedVersions.Keys)) { $mergedFixed[$k] = $FixedVersions[$k] }
$FixedVersions = $mergedFixed
foreach ($k in @($FixedVersions.Keys)) {
    if ($FixedVersions[$k] -notmatch '^\d+\.\d+\.\d+$') {
        Write-Warning ("FixedVersions['{0}'] = '{1}' is not N.N.N - ignored (branch treated as unmapped)" -f $k, $FixedVersions[$k])
        $FixedVersions.Remove($k)
    }
}

$suspicious = $false
$versionUndetermined = $false
$vulnerableVersion = $false
$report = [ordered]@{}
$scanErrors = @()
$scannedDirectories = @()
$missingDirectories = @()

Write-Host '=== PHP2Shell community detection - session & webroot artifact scan ===' -ForegroundColor Cyan

# --- 0. PHP version inventory ----------------------------------------------------
# Factual inventory of installed PHP builds. The fixed-version mapping is
# official (confirmed 2026-10-21, see README); verdicts are leads to review,
# not vendor confirmations. Comparison is NUMERIC, component-wise: a string comparison
# would misjudge e.g. 8.3.9 (vulnerable) as >= 8.3.36 because "9" > "3".
# Exit semantics: a version below the official fixed version is an exposure
# indicator (exit 1). A version that cannot be determined is a coverage gap,
# NOT a finding: it contributes to exit 2 (assessment incomplete), never to
# exit 1 on its own.
$report.PhpVersions = @()
$resolvedBins = @()
if ($PhpBins -and @($PhpBins).Count -gt 0) {
    $resolvedBins = @($PhpBins)
} else {
    $cmd = Get-Command php -ErrorAction SilentlyContinue
    if ($cmd) { $resolvedBins += $cmd.Source }
    foreach ($pat in 'C:\php*\php.exe', 'C:\Program Files\php*\php.exe', 'C:\Program Files\PHP\*\php.exe', 'C:\xampp\php\php.exe', 'C:\wamp*\bin\php\php*\php.exe') {
        $resolvedBins += (Get-ChildItem $pat -File -ErrorAction SilentlyContinue).FullName
    }
}
$phpBins = @($resolvedBins | Where-Object { $_ } | Select-Object -Unique)
foreach ($bin in $phpBins) {
    $verStr = $null
    # Timeout guard: a hung php -v must not stall fleet automation. The job
    # also reports the probe's exit code: a php -v that prints a version but
    # exits nonzero is an assessment gap, recorded in ScanErrors.
    $job = Start-Job {
        param($b)
        # Materialize BEFORE taking the first line: Select-Object -First in a
        # live native pipeline stops upstream and kills the process, losing
        # $LASTEXITCODE (the probe rc is part of the evidence).
        $v = @(& $b -v 2>$null) | Select-Object -First 1
        Write-Output ("RC:{0}" -f $LASTEXITCODE)
        Write-Output $v
    } -ArgumentList $bin
    if (Wait-Job $job -Timeout 10) {
        $out = @(Receive-Job $job)
        $probeRc = 0
        if ($out.Count -gt 0 -and "$($out[0])" -match '^RC:(-?\d+)$') { $probeRc = [int]$Matches[1] }
        $verStr = $out | Select-Object -Skip 1 -First 1
        if ($probeRc -ne 0) { $scanErrors += ("version probe exited rc={0} (output still parsed): {1}" -f $probeRc, $bin) }
    }
    else { Stop-Job $job; Write-Host ("[?] {0}  ->  version probe timed out - manual check required" -f $bin) -ForegroundColor Yellow; $versionUndetermined = $true; $scanErrors += "version probe timed out after 10s: $bin"; Remove-Job $job -Force; continue }
    Remove-Job $job -Force
    $ver = if ($verStr -match 'PHP (\d+\.\d+\.\d+)(\s|$)') { $Matches[1] } else { $null }
    $branch = if ($ver) { ($ver -split '\.')[0..1] -join '.' } else { $null }
    $fixed = if ($branch -and $FixedVersions.ContainsKey($branch)) { [string]$FixedVersions[$branch] } else { $null }

    if (-not $ver) {
        $status = 'version could not be determined - manual check required'
        $versionUndetermined = $true; $marker = '?'; $color = 'Yellow'
    } elseif (-not $fixed) {
        $status = "branch $branch - no official fixed version (EOL or unrecognized branch); manual review"
        $versionUndetermined = $true; $marker = '?'; $color = 'Yellow'
    } else {
        $cmp = $null
        try { $cmp = ([version]$ver -lt [version]$fixed) } catch { }
        if ($null -eq $cmp) {
            $status = 'version string could not be parsed - manual check required'
            $versionUndetermined = $true; $marker = '?'; $color = 'Yellow'
        } elseif ($cmp) {
            $status = "below official fixed version $fixed - exposure indicator; confirm against the vendor advisory"
            $vulnerableVersion = $true; $marker = '!!'; $color = 'Yellow'
        } else {
            $status = "at or above official fixed version $fixed"
            $marker = 'ok'; $color = 'Green'
        }
    }
    Write-Host ("[{0}] {1}  ->  {2}" -f $marker, $bin, $status) -ForegroundColor $color
    $report.PhpVersions += [pscustomobject]@{ Binary = $bin; Version = $ver; Branch = $branch; ProvisionalFixed = $fixed; Status = $status }
}
if (-not $phpBins) { Write-Host '[i] No PHP binary found on PATH or common locations - version inventory skipped.' }

# --- mtime heuristic window -----------------------------------------------------
# Rolling last 7 days by default; -SinceDate overrides it.
try {
    $since = if ($SinceDate) {
        [datetimeoffset]::Parse($SinceDate, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    } else { (Get-Date).ToUniversalTime().AddDays(-7) }
} catch { Write-Error 'SinceDate must be a valid date (UTC is assumed without an offset).'; exit 2 }
Write-Host ("[i] Webroot mtime heuristic window: files modified after {0:u} (rolling last 7 days by default; override with -SinceDate)" -f $since) -ForegroundColor Cyan

# --- 1. Session file suspicious-content scan -------------------------------------
# PHP tags or serialized objects inside session files are unusual and worth
# review. Their presence is an indicator only - it is not, by itself, confirmed
# exploitation or evidence of any specific technique.
$report.SessionEvidence = @()
foreach ($dir in $SessionPaths | Where-Object { $_ } | Select-Object -Unique) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { $missingDirectories += $dir; continue }
    $scannedDirectories += $dir
    Get-ChildItem -LiteralPath $dir -Filter 'sess_*' -File -Force -ErrorAction SilentlyContinue -ErrorVariable +scanErrors | ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue -ErrorVariable +scanErrors
        if ($content -cmatch 'upload_progress_') {
            # Markers case-SENSITIVE (PHP writes upload_progress_/O:/C: tokens
            # lowercase); PHP TAGS case-INSENSITIVE (the language allows <?PHP).
            $hasPhp = $content -imatch '<\?php'
            $hasObj = $content -cmatch '(O|C):\d+:"'
            if ($hasPhp -or $hasObj) {
                Write-Host ("[!!] Session file contains suspicious content (php_tag={0} serialized_obj={1}) - review required, not confirmation of exploitation: {2}" -f $hasPhp, $hasObj, $_.FullName) -ForegroundColor Red
                $suspicious = $true
                $report.SessionEvidence += [pscustomobject]@{ File = $_.FullName; ModTime = $_.LastWriteTimeUtc; HasPhpTag = $hasPhp; HasSerializedObject = $hasObj }
            }
        }
    }
}
if (-not $report.SessionEvidence) { Write-Host '[i] No session-content matches returned.' }

# --- 2. Webshell hunt in web roots (content-scored, mtime secondary) --------------
# mtime alone is noisy (deploys, plugin updates), so files are scored on CONTENT
# first; the mtime window is a secondary heuristic signal only.
$report.WebshellHunt = @()
$patterns = @(
    @{ Name = 'eval';              Re = '(?i)\beval\s*\(' },
    @{ Name = 'assert';            Re = '(?i)\bassert\s*\(' },
    @{ Name = 'exec_family';       Re = '(?i)\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(' },
    @{ Name = 'decoders';          Re = '(?i)\b(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(' },
    @{ Name = 'request_input';     Re = '(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[' },
    @{ Name = 'callback_vectors';  Re = '(?i)\b(call_user_func|create_function|array_map|usort|register_shutdown_function)\s*\(' },
    @{ Name = 'file_write_input';  Re = '(?i)\b(file_put_contents|fwrite)\s*\([^)]*\$_' },
    @{ Name = 'outbound_conn';     Re = '(?i)\b(curl_exec|fsockopen|stream_socket_client)\s*\(' }
)
foreach ($root in $WebRoots | Where-Object { $_ } | Select-Object -Unique) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { $missingDirectories += $root; continue }
    $scannedDirectories += $root
    Get-ChildItem -LiteralPath $root -Filter '*.php' -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable +scanErrors | ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue -ErrorVariable +scanErrors
        if ($null -eq $content) { return }
        $score = 0
        $matched = @()
        foreach ($p in $patterns) {
            if ($content -match $p.Re) { $score++; $matched += $p.Name }
        }
        $recent = $_.LastWriteTimeUtc -gt $since
        if ($score -ge 2 -or $recent) {
            $strong = $score -ge 2
            $strength = if ($strong) { 'STRONG' } else { 'WEAK (heuristic: recent mtime only - review required)' }
            Write-Host ("[{0}] {1} (score={2} patterns={3}) {4}" -f $(if ($strong) { '!!' } else { '?' }), $_.FullName, $score, ($matched -join ','), $strength) -ForegroundColor $(if ($strong) { 'Red' } else { 'Yellow' })
            $report.WebshellHunt += [pscustomobject]@{
                File = $_.FullName; ModTime = $_.LastWriteTimeUtc; Size = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue -ErrorVariable +scanErrors).Hash
                WebshellScore = $score; MatchedPatterns = $matched -join ','; Signal = $strength
            }
            if ($strong) { $suspicious = $true }
        }
    }
}
if (-not $report.WebshellHunt) { Write-Host '[i] No webroot matches returned.' }

# --- 3. Compare the web root against a clean copy (optional) ----------------------
# The fastest way to find what an attacker added or changed: diff the live
# tree against a trusted copy and look at what differs. ADDED and MODIFIED
# files are the suspect list. MISSING files can mean the attacker cleaned
# up after themselves. Evidence for the analyst: the diff never changes
# the exit code, because a stale clean copy would turn every normal deploy
# into a finding.
$report.WebrootDiff = @()
if ($DiffAgainst) {
    if (-not (Test-Path -LiteralPath $DiffAgainst -PathType Container)) {
        Write-Host 'DiffAgainst must be an existing directory (a clean copy of the web root).' -ForegroundColor Red
        exit 2
    }
    if (@($WebRoots).Count -gt 1) {
        Write-Host '[!] DiffAgainst compares every web root against the same clean copy. Use one web root per run when the trees differ.' -ForegroundColor Yellow
    }
    # Files are compared by content: symlinked files are hashed through
    # their target, and a file that cannot be hashed is skipped with a
    # warning rather than misclassified. Trailing separators are kept on
    # filesystem roots (TrimEnd would turn C:\ into drive-relative C:).
    $added = 0; $modified = 0; $missing = 0; $diffErrors = 0
    $cleanRoot = (Resolve-Path -LiteralPath $DiffAgainst).Path
    if ($cleanRoot.Length -gt 3) { $cleanRoot = $cleanRoot.TrimEnd('\') }
    foreach ($root in ($WebRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $rootPath = (Resolve-Path -LiteralPath $root).Path
        if ($rootPath.Length -gt 3) { $rootPath = $rootPath.TrimEnd('\') }
        $cleanSha = @{}; $cleanFailed = @{}
        foreach ($f in Get-ChildItem -LiteralPath $cleanRoot -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $rel = $f.FullName.Substring($cleanRoot.Length).TrimStart('\')
            $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if (-not $h) {
                Write-Warning "Web root diff: could not hash clean-copy file: $($f.FullName)"
                $diffErrors++
                $cleanFailed[$rel] = $true
                continue
            }
            $cleanSha[$rel] = $h
        }
        foreach ($f in Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $liveSha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if (-not $liveSha) {
                Write-Warning "Web root diff: could not hash live file: $($f.FullName)"
                $diffErrors++
                continue
            }
            $rel = $f.FullName.Substring($rootPath.Length).TrimStart('\')
            if ($cleanFailed.ContainsKey($rel)) { continue }
            $state = if (-not $cleanSha.ContainsKey($rel)) { 'ADDED' } elseif ($cleanSha[$rel] -ne $liveSha) { 'MODIFIED' } else { continue }
            if ($state -eq 'ADDED') { $added++ } else { $modified++ }
            Write-Host ("[!] Web root diff ({0}): {1}\{2}" -f $state, $rootPath, $rel) -ForegroundColor Yellow
            $report.WebrootDiff += [pscustomobject]@{ Webroot = $rootPath; Path = $rel; State = $state; SHA256 = $liveSha }
        }
        foreach ($rel in $cleanSha.Keys) {
            if (-not (Test-Path -LiteralPath (Join-Path $rootPath $rel) -PathType Leaf)) {
                $missing++
                Write-Host ("[!] Web root diff (MISSING): {0}\{1}" -f $rootPath, $rel) -ForegroundColor Yellow
                $report.WebrootDiff += [pscustomobject]@{ Webroot = $rootPath; Path = $rel; State = 'MISSING'; SHA256 = $cleanSha[$rel] }
            }
        }
    }
    if ($added -or $modified -or $missing) { Write-Host ("[i] Web root diff: {0} added, {1} modified, {2} missing." -f $added, $modified, $missing) }
    if ($diffErrors) { Write-Warning ("Web root diff: {0} file(s) could not be hashed and were excluded from the comparison." -f $diffErrors) }
}

# --- Summary ---------------------------------------------------------------------
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$weakOnly = @($report.WebshellHunt | Where-Object { $_.Signal -notlike 'STRONG*' })
if ($suspicious) {
    Write-Host 'Matching evidence found - review the findings above.' -ForegroundColor Yellow
} else {
    Write-Host 'No findings met the session/content threshold. Review scan coverage and any weak findings.'
}
if ($weakOnly -and -not $suspicious) {
    Write-Host ("Heuristic mtime-only findings were listed above ({0}); these are weak signals and require manual review." -f $weakOnly.Count) -ForegroundColor Yellow
}
$report.ScannedDirectories = @($scannedDirectories | Select-Object -Unique)
$report.MissingDirectories = @($missingDirectories | Select-Object -Unique)
$report.ScanErrors = @($scanErrors | ForEach-Object { $_.ToString() })
$incomplete = $scanErrors.Count -gt 0 -or $scannedDirectories.Count -eq 0
if ($incomplete) { Write-Warning 'Scan incomplete: errors occurred or no existing directories were scanned.' }
if ($versionUndetermined) { Write-Warning 'Assessment incomplete: PHP version could not be determined for one or more binaries (see PhpVersions in the report). This is a coverage gap, not a finding.' }
$report | ConvertTo-Json -Depth 4
exit $(if ($suspicious -or $vulnerableVersion) { 1 } elseif ($incomplete -or $versionUndetermined) { 2 } else { 0 })
