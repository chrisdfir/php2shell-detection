#!/usr/bin/env bash
# PHP2Shell-Check.sh - PHP2Shell community detection content: PHP version
# inventory, session-file and webroot artifact scan for Linux. Bash counterpart
# of PHP2Shell-Check.ps1.
#
# Standalone triage for admins - no Velociraptor required. This is community
# detection content: it looks for artifacts and inventories PHP versions.
# Checks:
#   0. PHP installations and versions, compared NUMERICALLY against a
#      official fixed-version mapping (confirmed 2026-10-21; still a lead
#      to review, not a vendor verdict - see README "PHP version inventory")
#   1. Session files containing PHP tags or serialized objects
#      (suspicious-content scan; indicators for review, not proof of exploitation)
#   2. .php files in web roots scored on webshell-indicator CONTENT, with a
#      recent-mtime window as a secondary heuristic signal
#
# Exit codes: 0 = no findings met any threshold and nothing was left
# unassessed. This is NOT a statement that the host is safe or
# uncompromised - absence of indicators is not absence of compromise.
#             1 = suspicious session-file content and/or strong webshell
# content findings and/or a PHP version below the official fixed version
# (see output for details).
#             2 = assessment incomplete with no threshold match: scan errors,
# no existing directories scanned, or a PHP version that could not be
# determined. An undetermined version is a coverage gap, NOT exposure
# evidence, so it never surfaces as exit code 1 on its own.
#
# Weak (mtime-only) webroot findings are heuristic and always require manual
# review; they do not by themselves set exit code 1.
#
# Output: human-readable progress and the summary go to stderr; the JSON
# report goes to stdout (so it can be piped: ./PHP2Shell-Check.sh > report.json).
#
# Requires: bash 4.4+, GNU coreutils (date -d, stat -c, sort -V), grep, find,
# sha256sum, and iconv (optional but recommended: without it, filenames with
# invalid UTF-8 pass through unconverted and can yield invalid JSON output).
#
# Author: Chris DiSalle (chrisdfir)

set -uo pipefail

# --- defaults (override with flags) -----------------------------------------------
# Common session save paths: /tmp (many distros/containers), Debian/Ubuntu
# (/var/lib/php/sessions, /var/lib/php5), RHEL/Remi (/var/lib/php/session).
SESSION_PATHS=(/tmp /var/lib/php/sessions /var/lib/php/session /var/lib/php5)
WEB_ROOTS=(/var/www/html /var/www /usr/share/nginx/html)
PHP_BINS=()
SINCE_ARG=""
FIXED_ARG=""
DIFF_ARG=""

# Official first-fixed-version per branch, confirmed against the php.net
# advisory and php-src GHSA advisories (2026-10-21). Re-verify against
# future advisories before acting on any verdict (see README).
declare -A FIXED_VERSIONS=( ['8.2']='8.2.35' ['8.3']='8.3.36' ['8.4']='8.4.27' ['8.5']='8.5.12' )

usage() {
    cat >&2 <<'USAGE'
Usage: ./PHP2Shell-Check.sh [options]

Options:
  -p, --session-paths <dir[,dir...]>   Session directories to scan (default:
                                       /tmp,/var/lib/php/sessions,
                                       /var/lib/php/session,/var/lib/php5)
  -w, --web-roots <dir[,dir...]>       Web roots to scan (default:
                                       /var/www/html,/var/www,
                                       /usr/share/nginx/html)
  -b, --php-bins <path[,path...]>      Explicit php executables to inventory.
                                       Default: PATH plus common install
                                       locations (discovered).
  -f, --fixed-versions <b=v[,b=v...]>  Override the official fixed-version
                                       mapping, e.g. 8.3=8.3.36,8.4=8.4.27
  -s, --since <ISO8601-UTC>            mtime heuristic window cutoff; UTC is
                                       assumed without an offset. Default:
                                       rolling last 7 days.
  -d, --diff-against <dir>             Compare each web root against a clean
                                       copy of the same tree. Reports files
                                       that were added, changed, or deleted.
                                       Evidence for the analyst: does not
                                       change the exit code. Use one web
                                       root per run.
  -h, --help                           Show this help.

Exit codes: 0 = no threshold findings, nothing unassessed; 1 = session-content,
score >= 2 webshell, or below-official-fixed PHP version matches; 2 =
assessment incomplete (scan errors, no directories scanned, or undetermined
PHP version) with no threshold match. A threshold match takes precedence.
USAGE
}

die_usage() { echo "Error: $1" >&2; usage; exit 2; }

# --- arg parsing --------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--session-paths)  [[ $# -ge 2 ]] || die_usage "$1 requires a value"; IFS=',' read -ra SESSION_PATHS <<< "$2"; shift 2 ;;
        -w|--web-roots)      [[ $# -ge 2 ]] || die_usage "$1 requires a value"; IFS=',' read -ra WEB_ROOTS <<< "$2"; shift 2 ;;
        -b|--php-bins)       [[ $# -ge 2 ]] || die_usage "$1 requires a value"; IFS=',' read -ra PHP_BINS <<< "$2"; shift 2 ;;
        -f|--fixed-versions) [[ $# -ge 2 ]] || die_usage "$1 requires a value"; FIXED_ARG=$2; shift 2 ;;
        -s|--since)          [[ $# -ge 2 ]] || die_usage "$1 requires a value"; SINCE_ARG=$2; shift 2 ;;
        -d|--diff-against)   [[ $# -ge 2 ]] || die_usage "$1 requires a value"; DIFF_ARG=$2; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   die_usage "unknown option: $1" ;;
    esac
done

if [[ -n $FIXED_ARG ]]; then
    IFS=',' read -ra _pairs <<< "$FIXED_ARG"
    for _pair in "${_pairs[@]}"; do
        [[ $_pair == *=* ]] || die_usage "invalid --fixed-versions entry: $_pair (expected branch=version)"
        # Exactly three numeric components: a partial version (e.g. 8.3=9)
        # would misclassify every build on that branch, and PS cannot cast it.
        [[ ${_pair#*=} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die_usage "invalid version in --fixed-versions entry: $_pair (must be N.N.N)"
        # Bound components like detected versions: an oversized component
        # (e.g. 8.3.18446744073709551616) overflows comparison arithmetic and
        # can invert the verdict toward false "patched".
        [[ ${_pair#*=} =~ \.([0-9]{8,}) ]] && die_usage "version component too large in --fixed-versions entry: $_pair (max 7 digits per component)"
        [[ ${_pair%%=*} =~ ^[0-9]+\.[0-9]+$ ]] || die_usage "invalid branch in --fixed-versions entry: $_pair (must be N.N)"
        FIXED_VERSIONS[${_pair%%=*}]=${_pair#*=}
    done
fi

info() { echo "[i] $*" >&2; }
warn() { echo "[!] $*" >&2; }
hit()  { echo "$1" >&2; }   # pre-formatted finding line

# --- mtime heuristic window -----------------------------------------------------------
# Rolling last 7 days by default; --since overrides it.
if [[ -n $SINCE_ARG ]]; then
    since_epoch=$(date -u -d "$SINCE_ARG" +%s 2>/dev/null) || {
        echo 'SinceDate must be a valid date (UTC is assumed without an offset).' >&2
        exit 2
    }
else
    since_epoch=$(date -u -d '7 days ago' +%s)
fi

# --- clean web root copy (for --diff-against) ------------------------------------------
# A trusted copy of the web root to diff against. Without it the diff step is
# skipped. It must exist, or the comparison would silently do nothing.
if [[ -n $DIFF_ARG && ! -d $DIFF_ARG ]]; then
    echo '--diff-against must be an existing directory (a clean copy of the web root).' >&2
    exit 2
fi
since_iso=$(date -u -d "@$since_epoch" +%Y-%m-%dT%H:%M:%SZ)
info "Webroot mtime heuristic window: files modified after ${since_iso} (rolling last 7 days by default; override with --since)"

# --- helpers ----------------------------------------------------------------------------
scan_errors=0
err_msgs=()
add_error() { scan_errors=$((scan_errors + 1)); err_msgs+=("$1"); }

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\b'/\\b}
    s=${s//$'\f'/\\f}
    s=${s//$'\t'/\\t}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    # Remaining control bytes (ESC, VT, ...) are invalid bare in JSON strings;
    # strip them (rare, and content is preserved printably).
    # Notable control bytes get explicit \u escapes; invalid UTF-8 bytes are
    # DROPPED via iconv (JSON validity over byte-perfect paths, documented):
    # a raw 0xFF byte in a filename would otherwise poison the whole report.
    # Capture conversion output SEPARATELY: some iconv implementations exit
    # nonzero after emitting partial output, and `|| printf` would then
    # APPEND the original (duplicating it and restoring invalid bytes).
    # Control-byte stripping runs ALWAYS (iconv handles encoding, not
    # controls). Residual edge: iconv failing with NO output keeps the
    # original bytes (minus controls), preferred over emitting nothing.
    s=${s//$'\x0b'/\\u000b}
    s=${s//$'\x1b'/\\u001b}
    if command -v iconv >/dev/null 2>&1; then
        # Capture separately (never append partial output to the original).
        # GUARANTEED valid UTF-8 on every path: success takes the conversion
        # (even when empty - an entirely-invalid input sanitizes to empty);
        # failure takes partial output if any, else drops the input entirely.
        # Restoring raw original bytes would risk an unparseable report.
        conv=$(printf '%s' "$s" | iconv -t UTF-8 -c 2>/dev/null)
        rc=$?
        if (( rc == 0 )) || [[ -n $conv ]]; then s=$conv; else s=""; fi
    fi
    s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
    printf '%s' "$s"
}

json_str() { # value -> JSON string, or null when empty
    local v=$1
    if [[ -z $v ]]; then echo null; else echo "\"$(json_escape "$v")\""; fi
}

iso_of() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; }

# Numeric component-wise version less-than. Components are compared as
# INTEGERS after stripping leading zeros: sort -V treats "8.3.036" < "8.3.36"
# (string padding artifact) while [version] calls them equal.
ver_lt() {
    local a=$1 b=$2
    [[ $a == "$b" ]] && return 1
    local -a A B
    IFS=. read -ra A <<< "$a"
    IFS=. read -ra B <<< "$b"
    local i x y
    for ((i = 0; i < ${#A[@]} || i < ${#B[@]}; i++)); do
        x=${A[i]:-0}; y=${B[i]:-0}
        x=$((10#$x)); y=$((10#$y))
        if (( x < y )); then return 0; fi
        if (( x > y )); then return 1; fi
    done
    return 1
}

# Dedupe, drop empties (mirrors PS1 Where-Object { $_ } | Select-Object -Unique)
dedupe() { printf '%s\n' "$@" | awk 'NF && !seen[$0]++'; }

suspicious=0
version_undetermined=0
vulnerable_version=0
scanned=0
php_json=()
session_json=()
webshell_json=()
scanned_dirs=()
missing_dirs=()

echo '=== PHP2Shell community detection - session & webroot artifact scan ===' >&2

# --- 0. PHP version inventory -------------------------------------------------------------
# Factual inventory of installed PHP builds. The fixed-version mapping is
# official (confirmed 2026-10-21, see README); verdicts are leads to review,
# not vendor confirmations. Comparison is NUMERIC, component-wise. Exit
# semantics: a version below the official fixed version is an exposure
# indicator (exit 1). A version that cannot be determined is a coverage gap,
# NOT a finding: it contributes to exit 2 (assessment incomplete), never to
# exit 1 on its own.
if (( ${#PHP_BINS[@]} )); then
    php_bins=("${PHP_BINS[@]}")
else
    php_bins=()
    cmd_php=$(command -v php 2>/dev/null) && php_bins+=("$cmd_php")
    shopt -s nullglob
    for g in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/php[0-9]* \
             /opt/php*/bin/php /usr/local/php*/bin/php; do
        [[ -x $g ]] && php_bins+=("$g")
    done
    shopt -u nullglob
fi
# dedupe while preserving order, drop empties
if (( ${#php_bins[@]} )); then
    mapfile -t php_bins < <(dedupe "${php_bins[@]}")
fi
for bin in "${php_bins[@]:-}"; do
    [[ -n $bin ]] || continue
    ver=""; branch=""; fixed=""
    if [[ -x $bin ]]; then
        prc=0
        # Capture COMPLETE output before selecting the first line: piping the
        # live probe into head closes the pipe early and SIGPIPEs a healthy
        # multi-line php -v (rc=141 -> spurious assessment gap).
        verout=$(timeout 10 "$bin" -v 2>/dev/null); prc=$?
        verline=$(printf '%s' "$verout" | head -n1)
        # A failed/timed-out probe is an assessment gap, not a non-match.
        (( prc != 0 )) && add_error "version probe failed (rc=$prc): $bin"
        # Full-token match: a suffix such as 8.3.36-dev or 8.3.36.1 must NOT
        # be truncated to 8.3.36 (that would clear a prerelease/unknown build).
        if [[ $verline =~ PHP\ ([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]|$) ]]; then
            ver=${BASH_REMATCH[1]}
            # Bound components before bash arithmetic: an oversized component
            # (e.g. a garbage banner) overflows 64-bit math and inverts the
            # verdict. Undetermined is the honest result for such output.
            if [[ ${#ver} -gt 23 || $ver =~ \.([0-9]{8,}) ]]; then
                ver=""
            fi
            branch=${ver%.*}
            fixed=${FIXED_VERSIONS[$branch]:-}
        fi
    else
        add_error "php binary not executable: $bin"
        continue
    fi

    if [[ -z $ver ]]; then
        status='version could not be determined - manual check required'
        version_undetermined=1; marker='?'
    elif [[ -z $fixed ]]; then
        status="branch $branch - no official fixed version (EOL or unrecognized branch); manual review"
        version_undetermined=1; marker='?'
    elif ver_lt "$ver" "$fixed"; then
        status="below official fixed version $fixed - exposure indicator; confirm against the vendor advisory"
        vulnerable_version=1; marker='!!'
    else
        status="at or above official fixed version $fixed"
        marker='ok'
    fi
    hit "[$marker] $bin  ->  $status"
    php_json+=("{\"Binary\":\"$(json_escape "$bin")\",\"Version\":$(json_str "$ver"),\"Branch\":$(json_str "$branch"),\"FixedVersion\":$(json_str "$fixed"),\"Status\":\"$(json_escape "$status")\"}")
done
if ! (( ${#php_bins[@]} )); then
    info 'No PHP binary found on PATH or common locations - version inventory skipped.'
fi

# --- 1. Session file suspicious-content scan -----------------------------------------------
# PHP tags or serialized objects inside session files are unusual and worth
# review. Their presence is an indicator only - it is not, by itself, confirmed
# exploitation or evidence of any specific technique.
while IFS= read -r dir; do
    [[ -n $dir ]] || continue
    if [[ ! -d $dir ]]; then
        missing_dirs+=("$dir")
        continue
    fi
    if [[ ! -r $dir || ! -x $dir ]]; then
        add_error "cannot read directory: $dir"
        continue
    fi
    # mktemp BEFORE counting as scanned: a failed temp file (disk full,
    # unusable TMPDIR) must not silently disable enumeration while the
    # directory still counts as covered (false-confidence exit 0).
    ferr=$(mktemp) || { add_error "mktemp failed - directory not scanned: $dir"; continue; }
    scanned=$((scanned + 1))
    scanned_dirs+=("$dir")
    while IFS= read -r -d '' f; do
        if [[ ! -r $f ]]; then
            add_error "cannot read file: $f"
            continue
        fi
        grc=0; grep -q 'upload_progress_' "$f" 2>/dev/null || grc=$?
        (( grc == 2 )) && add_error "grep failed on: $f"
        (( grc != 0 )) && continue
        # Case-insensitive tag (PS parity); objects: any O:/C: serializer form,
        # including nested arrays (a:1:{i:0;O:8:"…"}) and pipeless php_serialize.
        has_php=0; grcP=0
        # PHP tags are case-insensitive in the language itself (<?PHP is valid);
        # upload_progress_/O:/C: markers are lowercase-by-convention (sensitive).
        grep -qiF '<?php' "$f" 2>/dev/null && has_php=1
        grcP=$?
        has_obj=0; grcO=0
        grep -qE '(O|C):[0-9]+:"' "$f" 2>/dev/null && has_obj=1
        grcO=$?
        (( grcP == 2 || grcO == 2 )) && add_error "content grep failed on: $f"
        if ((has_php || has_obj)); then
            suspicious=1
            m_epoch=$(stat -c %Y "$f" 2>/dev/null) || { m_epoch=""; add_error "stat failed on: $f"; }
            hit "[!!] Session file contains suspicious content (php_tag=${has_php} serialized_obj=${has_obj}) - review required, not confirmation of exploitation: ${f}"
            session_json+=("{\"File\":\"$(json_escape "$f")\",\"ModTime\":\"$(iso_of "${m_epoch:-}")\",\"HasPhpTag\":${has_php},\"HasSerializedObject\":${has_obj}}")
        fi
    done < <(find -H "$dir" -maxdepth 1 -type f -name 'sess_*' -print0 2>"$ferr")
    if [[ -s $ferr ]]; then add_error "session scan traversal errors in $dir: $(head -n1 "$ferr")"; fi
    rm -f "$ferr"
done < <(dedupe "${SESSION_PATHS[@]}")
(( ${#session_json[@]} )) || info 'No session-content matches returned.'

# --- 2. Webshell hunt in web roots (content-scored, mtime secondary) -------------------------
# mtime alone is noisy (deploys, plugin updates), so files are scored on CONTENT
# first; the mtime window is a secondary heuristic signal only.
# Same eight pattern families as PHP2Shell-Check.ps1 (name::ERE, case-insensitive).
patterns=(
    'eval::\beval[[:space:]]*\('
    'assert::\bassert[[:space:]]*\('
    'exec_family::\b(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\('
    'decoders::\b(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)[[:space:]]*\('
    'request_input::\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\['
    'callback_vectors::\b(call_user_func|create_function|array_map|usort|register_shutdown_function)[[:space:]]*\('
    'file_write_input::\b(file_put_contents|fwrite)[[:space:]]*\([^)]*\$_'
    'outbound_conn::\b(curl_exec|fsockopen|stream_socket_client)[[:space:]]*\('
)
while IFS= read -r root; do
    [[ -n $root ]] || continue
    if [[ ! -d $root ]]; then
        missing_dirs+=("$root")
        continue
    fi
    if [[ ! -r $root || ! -x $root ]]; then
        add_error "cannot read directory: $root"
        continue
    fi
    # mktemp BEFORE counting as scanned (see session loop above).
    ferr=$(mktemp) || { add_error "mktemp failed - directory not scanned: $root"; continue; }
    scanned=$((scanned + 1))
    scanned_dirs+=("$root")
    while IFS= read -r -d '' f; do
        if [[ ! -r $f ]]; then
            add_error "cannot read file: $f"
            continue
        fi
        score=0
        matched=()
        grcW=0
        for p in "${patterns[@]}"; do
            name=${p%%::*}
            re=${p#*::}
            # -z: treat the whole file as one record so [[:space:]] spans
            # newlines (PS -match parity for calls split across lines).
            grc=0
            grep -zEqi "$re" "$f" 2>/dev/null || grc=$?
            if (( grc == 0 )); then
                score=$((score + 1))
                matched+=("$name")
            elif (( grc == 2 )); then
                grcW=1
            fi
        done
        (( grcW )) && add_error "content grep failed on: $f"
        m_epoch=$(stat -c %Y "$f" 2>/dev/null) || { m_epoch=""; add_error "stat failed on: $f"; }
        if [[ -n $m_epoch ]] && (( m_epoch > since_epoch )); then recent=1; else recent=0; fi
        if (( score >= 2 || recent )); then
            if (( score >= 2 )); then
                strong=1; tag='!!'; strength='STRONG'
            else
                strong=0; tag='?'; strength='WEAK (heuristic: recent mtime only - review required)'
            fi
            size=$(stat -c %s "$f" 2>/dev/null) || { size=""; add_error "size stat failed on: $f"; }
            # Strip the leading backslash sha256sum prepends to escaped-name
            # records; a raw backslash would break the JSON string.
            sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' | tr -d '\\')
            [[ -z $sha ]] && add_error "hash failed on: $f"
            hit "[${tag}] ${f} (score=${score} patterns=$(IFS=,; echo "${matched[*]-}")) ${strength}"
            webshell_json+=("{\"File\":\"$(json_escape "$f")\",\"ModTime\":\"$(iso_of "${m_epoch:-}")\",\"Size\":${size:-null},\"SHA256\":\"${sha:-}\",\"WebshellScore\":${score},\"MatchedPatterns\":\"$(json_escape "$(IFS=,; echo "${matched[*]-}")")\",\"Signal\":\"$(json_escape "$strength")\"}")
            (( strong )) && suspicious=1
        fi
    done < <(find -H "$root" -type f -iname '*.php' -print0 2>"$ferr")
    if [[ -s $ferr ]]; then add_error "webroot scan traversal errors in $root: $(head -n1 "$ferr")"; fi
    rm -f "$ferr"
done < <(dedupe "${WEB_ROOTS[@]}")
(( ${#webshell_json[@]} )) || info 'No webroot matches returned.'

# --- 3. Compare the web root against a clean copy (optional) -------------------
# The fastest way to find what an attacker added or changed: diff the live
# tree against a trusted copy and look at what differs. ADDED and MODIFIED
# files are the suspect list. MISSING files can mean the attacker cleaned
# up after themselves. This is evidence for the analyst: it never changes
# the exit code, because a stale clean copy would turn every normal deploy
# into a finding.
diff_json=()
if [[ -n $DIFF_ARG ]]; then
    if (( ${#WEB_ROOTS[@]} > 1 )); then
        warn '--diff-against compares every web root against the same clean copy. Use one web root per run when the trees differ.'
    fi
    added=0; modified=0; missing=0; diff_errors=0
    # Trailing slashes are normalized so prefix stripping works, including
    # the filesystem root itself (an empty dir string strips only the
    # separator). Files are compared by content: symlinks to regular files
    # are hashed through their target, and a file that cannot be hashed is
    # excluded with a warning rather than misclassified; the live
    # counterpart of an unhashable clean file is also excluded.
    clean=${DIFF_ARG%/}; [[ -z $clean ]] && clean=/
    cleandir=${clean%/}
    while IFS= read -r root; do
        [[ -d $root ]] || continue
        root=${root%/}; [[ -z $root ]] && root=/
        rootdir=${root%/}
        declare -A clean_sha=() clean_failed=()
        while IFS= read -r -d '' f; do
            rel=${f#"${cleandir}/"}
            csha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' | tr -d '\\')
            if [[ -z $csha ]]; then
                warn "Web root diff: could not hash clean-copy file: $f"
                diff_errors=$((diff_errors+1))
                clean_failed["$rel"]=1
                continue
            fi
            clean_sha["$rel"]=$csha
        done < <(find -H "$clean" \( -type f -o -xtype f \) -print0 2>/dev/null)
        while IFS= read -r -d '' f; do
            rel=${f#"${rootdir}/"}
            lsha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' | tr -d '\\')
            if [[ -z $lsha ]]; then
                warn "Web root diff: could not hash live file: $f"
                diff_errors=$((diff_errors+1))
                continue
            fi
            [[ -n ${clean_failed[$rel]+x} ]] && continue
            if [[ -z ${clean_sha[$rel]+x} ]]; then state=ADDED
            elif [[ ${clean_sha[$rel]} != "$lsha" ]]; then state=MODIFIED
            else continue; fi
            if [[ $state == ADDED ]]; then added=$((added+1)); else modified=$((modified+1)); fi
            hit "[!] Web root diff ($state): ${rootdir}/$rel"
            diff_json+=("{\"Webroot\":\"$(json_escape "$root")\",\"Path\":\"$(json_escape "$rel")\",\"State\":\"$state\",\"SHA256\":\"$lsha\"}")
        done < <(find -H "$root" \( -type f -o -xtype f \) -print0 2>/dev/null)
        for rel in "${!clean_sha[@]}"; do
            [[ -f "${rootdir}/$rel" ]] || { missing=$((missing+1)); hit "[!] Web root diff (MISSING): ${rootdir}/$rel"; diff_json+=("{\"Webroot\":\"$(json_escape "$root")\",\"Path\":\"$(json_escape "$rel")\",\"State\":\"MISSING\",\"SHA256\":\"${clean_sha[$rel]}\"}"); }
        done
    done < <(dedupe "${WEB_ROOTS[@]}")
    if (( added || modified || missing )); then
        info "Web root diff: $added added, $modified modified, $missing missing."
    fi
    (( diff_errors )) && warn "Web root diff: $diff_errors file(s) could not be hashed and were excluded from the comparison."
fi

# --- Summary ----------------------------------------------------------------------------------
echo '=== Summary ===' >&2
weak_only=0
for o in "${webshell_json[@]:-}"; do
    [[ $o == *'WEAK (heuristic'* ]] || continue
    [[ $o == *'STRONG'* ]] && continue
    weak_only=$((weak_only + 1))
done
if (( suspicious || vulnerable_version )); then
    warn 'Matching evidence found - review the findings above.'
else
    info 'No findings met the session/content threshold. Review scan coverage and any weak findings.'
fi
if (( weak_only && ! suspicious && ! vulnerable_version )); then
    warn "Heuristic mtime-only findings were listed above (${weak_only}); these are weak signals and require manual review."
fi

incomplete=0
(( scan_errors > 0 || scanned == 0 || version_undetermined )) && incomplete=1
(( incomplete )) && warn 'Scan incomplete: errors occurred, no existing directories were scanned, or a PHP version could not be determined.'

# --- JSON report (stdout) ----------------------------------------------------------------------
str_array() {
    local out=() x
    while IFS= read -r x; do
        [[ -n $x ]] || continue
        out+=("\"$(json_escape "$x")\"")
    done < <(dedupe "$@")
    local IFS=,
    echo "[${out[*]-}]"
}
join_array() { local IFS=,; echo "[$*]"; }

cat <<JSON
{
  "PhpVersions": $(join_array "${php_json[@]:-}"),
  "SessionEvidence": $(join_array "${session_json[@]:-}"),
  "WebshellHunt": $(join_array "${webshell_json[@]:-}"),
  "WebrootDiff": $(join_array "${diff_json[@]:-}"),
  "ScannedDirectories": $(str_array "${scanned_dirs[@]:-}"),
  "MissingDirectories": $(str_array "${missing_dirs[@]:-}"),
  "ScanErrors": $(str_array "${err_msgs[@]:-}")
}
JSON

if (( suspicious || vulnerable_version )); then exit 1; fi
if (( incomplete )); then exit 2; fi
exit 0
