#!/usr/bin/env bash
# Hunt running Linux processes for environment variables that can alter code loading.
# Read-only: variable values are never printed, and processes are not modified.
#
# Examples:
#   sudo ./process_environment_injection_hunt.sh
#   ./process_environment_injection_hunt.sh -i 1234
#   sudo ./process_environment_injection_hunt.sh -o environment-injection-report.txt
#
# Exit codes: 0 no findings, 1 review findings present, 2 input/collection error.

set -uo pipefail
umask 077

proc_root=/proc
target_pid=""
output=""

usage() {
  cat <<'USAGE'
Usage: process_environment_injection_hunt.sh [-i PID] [-p PROC_DIR] [-o REPORT]

Options:
  -i PID     Inspect one process instead of every visible process
  -p DIR     procfs root (default: /proc)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The hunt reports variable names only, never values. High-severity indicators
include LD_PRELOAD, LD_AUDIT, and GCONV_PATH. Interpreter startup and search-path
variables are medium-severity review leads. Legitimate profilers, development
tools, and managed runtimes may set these variables intentionally.
USAGE
}

while getopts ":i:p:o:h" option; do
  case "$option" in
    i) target_pid=$OPTARG ;;
    p) proc_root=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n $target_pid && ! $target_pid =~ ^[1-9][0-9]*$ ]]; then
  printf 'PID must be a positive integer: %s\n' "$target_pid" >&2
  exit 2
fi

if [[ ! -d $proc_root ]]; then
  printf 'procfs directory was not found: %s\n' "$proc_root" >&2
  exit 2
fi

tmp_findings=$(mktemp)
tmp_warnings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_findings" "$tmp_warnings" "$tmp_report"' EXIT

process_count=0
unreadable_count=0
finding_count=0
high_count=0
medium_count=0

if [[ -n $target_pid ]]; then
  process_dirs=("$proc_root/$target_pid")
  [[ -d ${process_dirs[0]} ]] || {
    printf 'Process was not found under %s: %s\n' "$proc_root" "$target_pid" >&2
    exit 2
  }
else
  process_dirs=("$proc_root"/[0-9]*)
fi

for process_dir in "${process_dirs[@]}"; do
  [[ -d $process_dir ]] || continue
  pid=${process_dir##*/}
  [[ $pid =~ ^[0-9]+$ ]] || continue
  process_count=$((process_count + 1))

  if [[ ! -r $process_dir/environ ]]; then
    unreadable_count=$((unreadable_count + 1))
    printf 'PID %s environment is not readable\n' "$pid" >>"$tmp_warnings"
    continue
  fi

  comm=unknown
  [[ -r $process_dir/comm ]] && IFS= read -r comm <"$process_dir/comm" || true
  uid=unknown
  if [[ -r $process_dir/status ]]; then
    uid=$(awk '/^Uid:/ {print $2; exit}' "$process_dir/status" 2>/dev/null)
    [[ -n $uid ]] || uid=unknown
  fi
  executable=$(readlink "$process_dir/exe" 2>/dev/null || printf unavailable)

  severity=OK
  indicators=()
  while IFS= read -r -d '' entry; do
    variable=${entry%%=*}
    case "$variable" in
      LD_PRELOAD|LD_AUDIT|GCONV_PATH)
        severity=HIGH
        indicators+=("$variable")
        ;;
      LD_LIBRARY_PATH|BASH_ENV|ENV|PYTHONPATH|PYTHONINSPECT|PERL5LIB|PERL5OPT|RUBYLIB|RUBYOPT|NODE_OPTIONS)
        [[ $severity == HIGH ]] || severity=MEDIUM
        indicators+=("$variable")
        ;;
    esac
  done <"$process_dir/environ"

  (( ${#indicators[@]} > 0 )) || continue
  indicator_text=$(IFS=,; printf '%s' "${indicators[*]}")
  safe_comm=${comm//$'\t'/ }
  safe_comm=${safe_comm//$'\n'/ }
  safe_executable=${executable//$'\t'/ }
  safe_executable=${safe_executable//$'\n'/ }
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$severity" "$pid" "$uid" "$safe_comm" "$safe_executable" "$indicator_text" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
  if [[ $severity == HIGH ]]; then
    high_count=$((high_count + 1))
  else
    medium_count=$((medium_count + 1))
  fi
done

if (( process_count == 0 )); then
  printf 'No process directories were found under: %s\n' "$proc_root" >&2
  exit 2
fi

{
  printf 'Process Environment Injection Hunt\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'procfs source: %s\n' "$proc_root"
  [[ -n $target_pid ]] && printf 'Target PID: %s\n' "$target_pid"
  printf 'Processes inspected: %d\n' "$process_count"
  printf 'Unreadable environments: %d\n' "$unreadable_count"
  printf 'Review findings: %d (high: %d, medium: %d)\n' \
    "$finding_count" "$high_count" "$medium_count"

  printf '\n== Processes requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No monitored code-loading environment variables were identified.\n'
  else
    printf 'SEVERITY | PID | UID | COMMAND | EXECUTABLE | VARIABLE NAMES\n'
    sort -t $'\t' -k1,1 -k2,2n "$tmp_findings" | tr '\t' '|'
  fi

  printf '\n== Collection warnings ==\n'
  if [[ -s $tmp_warnings ]]; then
    sort -u "$tmp_warnings"
  else
    printf 'None.\n'
  fi

  printf '\n== Investigation guidance ==\n'
  printf 'Confirm the process owner, parent, executable provenance, service unit, and expected runtime tooling.\n'
  printf 'Capture volatile evidence before termination; inspect variable values directly only with proper authorization.\n'
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

(( finding_count == 0 )) && exit 0
exit 1
