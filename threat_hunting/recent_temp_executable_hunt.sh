#!/usr/bin/env bash
# Hunt for recently modified executable files staged in temporary directories.
# Read-only: this script does not quarantine, delete, or execute discovered files.
#
# Examples:
#   sudo ./recent_temp_executable_hunt.sh
#   ./recent_temp_executable_hunt.sh -a 3 -d /tmp -d /dev/shm
#   sudo ./recent_temp_executable_hunt.sh -o temp-executable-report.txt
#
# Exit codes: 0 no candidates, 1 candidates require review, 2 input/collection error.

set -uo pipefail
umask 077

age_days=7
output=""
declare -a scan_dirs=()

usage() {
  cat <<'USAGE'
Usage: recent_temp_executable_hunt.sh [-a DAYS] [-d DIR]... [-o REPORT]

Options:
  -a DAYS    Include files modified within this many days (default: 7)
  -d DIR     Directory to inspect; may be repeated
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

With no -d options, the script inspects /tmp, /var/tmp, and /dev/shm when
present. It reports recent regular files that have an executable mode bit or a
script shebang. Severity increases for setuid/setgid or world-writable files.
Review findings in context; package installers and administrators may create
legitimate temporary executables.
USAGE
}

while getopts ":a:d:o:h" option; do
  case "$option" in
    a) age_days=$OPTARG ;;
    d) scan_dirs+=("$OPTARG") ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $age_days =~ ^[1-9][0-9]*$ ]]; then
  printf 'DAYS must be a positive integer: %s\n' "$age_days" >&2
  exit 2
fi

if (( ${#scan_dirs[@]} == 0 )); then
  for default_dir in /tmp /var/tmp /dev/shm; do
    [[ -d $default_dir ]] && scan_dirs+=("$default_dir")
  done
fi

if (( ${#scan_dirs[@]} == 0 )); then
  printf 'No scan directories are available.\n' >&2
  exit 2
fi

for scan_dir in "${scan_dirs[@]}"; do
  if [[ ! -d $scan_dir ]]; then
    printf 'Scan directory was not found: %s\n' "$scan_dir" >&2
    exit 2
  fi
done

tmp_candidates=$(mktemp)
tmp_errors=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_candidates" "$tmp_errors" "$tmp_report"' EXIT

candidate_count=0
critical_count=0
high_count=0
medium_count=0
files_examined=0

for scan_dir in "${scan_dirs[@]}"; do
  while IFS= read -r -d '' path; do
    files_examined=$((files_examined + 1))

    metadata=$(stat -Lc '%a|%U|%G|%s|%y' -- "$path" 2>/dev/null) || {
      printf 'Unable to read metadata: %s\n' "$path" >>"$tmp_errors"
      continue
    }
    IFS='|' read -r mode owner group size modified <<<"$metadata"
    permission_value=$((8#$mode))
    shebang=no
    [[ $(head -c 2 -- "$path" 2>/dev/null) == '#!' ]] && shebang=yes
    (( (permission_value & 0111) != 0 )) || [[ $shebang == yes ]] || continue

    severity=HIGH
    reasons=()

    (( (permission_value & 0111) != 0 )) && reasons+=('executable mode')
    [[ $shebang == yes ]] && reasons+=('script shebang')

    if (( (permission_value & 06000) != 0 )); then
      severity=CRITICAL
      reasons+=('setuid/setgid')
    fi
    if (( (permission_value & 0002) != 0 )); then
      severity=CRITICAL
      reasons+=('world writable')
    fi

    base=${path##*/}
    if [[ $base == .* && $severity != CRITICAL ]]; then
      reasons+=('hidden filename')
    fi

    hash=unavailable
    if command -v sha256sum >/dev/null 2>&1; then
      hash=$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')
      [[ -n $hash ]] || hash=unavailable
    fi

    safe_path=${path//$'\n'/\\n}
    safe_path=${safe_path//$'\t'/\\t}
    reason_text=$(IFS=', '; printf '%s' "${reasons[*]}")
    printf '%s\t%s\t%s\t%s:%s\t%s\t%s\t%s\n' \
      "$severity" "$safe_path" "$mode" "$owner" "$group" "$size" \
      "${modified%%.*}" "$hash | $reason_text" >>"$tmp_candidates"

    candidate_count=$((candidate_count + 1))
    case "$severity" in
      CRITICAL) critical_count=$((critical_count + 1)) ;;
      HIGH) high_count=$((high_count + 1)) ;;
      MEDIUM) medium_count=$((medium_count + 1)) ;;
    esac
  done < <(find "$scan_dir" -xdev -type f -mtime "-$age_days" -print0 2>>"$tmp_errors")
done

{
  printf 'Recent Temporary Executable Hunt\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Age window: %s day(s)\n' "$age_days"
  printf 'Directories:'
  printf ' %s' "${scan_dirs[@]}"
  printf '\nFiles examined: %d\n' "$files_examined"
  printf 'Candidates: %d (critical: %d, high: %d, medium: %d)\n' \
    "$candidate_count" "$critical_count" "$high_count" "$medium_count"

  printf '\n== Candidates requiring review ==\n'
  if (( candidate_count == 0 )); then
    printf 'No recent executable files or shebang scripts were found.\n'
  else
    printf 'SEVERITY | PATH | MODE | OWNER:GROUP | BYTES | MODIFIED | SHA256 / REASONS\n'
    sort -t $'\t' -k1,1 -k2,2 "$tmp_candidates" | tr '\t' '|'
  fi

  printf '\n== Collection warnings ==\n'
  if [[ -s $tmp_errors ]]; then
    sort -u "$tmp_errors"
  else
    printf 'None.\n'
  fi

  printf '\n== Investigation guidance ==\n'
  printf 'Confirm file provenance, parent process, owner, timestamps, and hash reputation.\n'
  printf 'Do not execute a candidate. Preserve evidence before containment or removal.\n'
} >"$tmp_report"

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output" || {
    printf 'Unable to write report: %s\n' "$output" >&2
    exit 2
  }
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( candidate_count == 0 )) && exit 0
exit 1
