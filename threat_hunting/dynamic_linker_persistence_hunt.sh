#!/usr/bin/env bash
# Hunt for Linux dynamic-linker preload and audit persistence indicators.
#
# Usage:
#   dynamic_linker_persistence_hunt.sh [-r ROOT] [-o REPORT]
#
# Options:
#   -r ROOT     Alternate filesystem root to inspect (default: /).
#   -o REPORT   Save the report with mode 600 instead of printing it.
#   -h          Show this help.
#
# The hunt checks /etc/ld.so.preload and common shell/systemd environment
# locations for LD_PRELOAD or LD_AUDIT assignments. These settings can be
# legitimate, so validate each finding against approved software and packages.
# The script is read-only. Exit codes: 0 no indicators; 1 indicators found;
# 2 invalid input or collection failure.

set -uo pipefail
umask 077

usage() {
  sed -n '2,15s/^# \{0,1\}//p' "$0"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

scan_root='/'
output=''
while getopts ':r:o:h' option; do
  case "$option" in
    r) scan_root=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "-$OPTARG requires an argument" ;;
    \?) die "unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))
(( $# == 0 )) || die 'unexpected positional arguments'
[[ -d $scan_root ]] || die "scan root is not a directory: $scan_root"

for command in cat chmod cp date dirname find mktemp rm sort; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

work_dir=$(mktemp -d) || die 'could not create temporary directory'
trap 'rm -rf -- "$work_dir"' EXIT
candidate_file=$work_dir/candidates
finding_file=$work_dir/findings
report_file=$work_dir/report
: >"$candidate_file"
: >"$finding_file"

display_path() {
  local path=$1
  if [[ $scan_root == '/' ]]; then
    printf '%s' "$path"
  else
    printf '/%s' "${path#"${scan_root%/}"/}"
  fi
}

record_finding() {
  local severity=$1 source=$2 line_number=$3 indicator=$4 detail=$5
  detail=${detail//$'\t'/ }
  detail=${detail//$'\n'/ }
  source=${source//$'\t'/ }
  printf '%s\t%s\t%s\t%s\t%.160s\n' \
    "$severity" "$source" "$line_number" "$indicator" "$detail" >>"$finding_file"
}

preload_file=${scan_root%/}/etc/ld.so.preload
if [[ -f $preload_file ]]; then
  line_number=0
  while IFS= read -r line || [[ -n $line ]]; do
    ((line_number += 1))
    [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
    record_finding 'HIGH' "$(display_path "$preload_file")" "$line_number" \
      'ld.so.preload' "$line"
  done <"$preload_file"
fi

for relative in etc/environment etc/profile etc/bash.bashrc; do
  path=${scan_root%/}/$relative
  [[ -f $path ]] && printf '%s\0' "$path" >>"$candidate_file"
done

for relative_dir in etc/profile.d etc/systemd/system etc/systemd/user; do
  directory=${scan_root%/}/$relative_dir
  if [[ -d $directory ]]; then
    find "$directory" -type f -print0 >>"$candidate_file" || \
      die "could not inspect: $(display_path "$directory")"
  fi
done

while IFS= read -r -d '' path; do
  line_number=0
  while IFS= read -r line || [[ -n $line ]]; do
    ((line_number += 1))
    [[ $line =~ ^[[:space:]]*# ]] && continue
    if [[ $line =~ (LD_PRELOAD|LD_AUDIT)[[:space:]]*= ]]; then
      indicator=${BASH_REMATCH[1]}
      record_finding 'HIGH' "$(display_path "$path")" "$line_number" "$indicator" "$line"
    fi
  done <"$path"
done <"$candidate_file"

sort -t $'\t' -k2,2 -k3,3n "$finding_file" -o "$finding_file" || die 'could not sort findings'
finding_count=0
while IFS= read -r _; do ((finding_count += 1)); done <"$finding_file"

{
  printf 'Dynamic linker persistence hunt\n'
  printf 'Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Scan root: %s\n\n' "$scan_root"
  printf '%-8s %-38s %-6s %-14s %s\n' 'SEVERITY' 'SOURCE' 'LINE' 'INDICATOR' 'DETAIL'
  printf '%-8s %-38s %-6s %-14s %s\n' '--------' '--------------------------------------' '------' '--------------' '------'
  while IFS=$'\t' read -r severity source line_number indicator detail; do
    printf '%-8s %-38s %-6s %-14s %s\n' \
      "$severity" "$source" "$line_number" "$indicator" "$detail"
  done <"$finding_file"
  printf '\nSummary: %d indicator(s) found\n' "$finding_count"
  if (( finding_count > 0 )); then
    printf 'Triage: confirm the referenced libraries, owning packages, file hashes, and change history.\n'
  fi
} >"$report_file"

if [[ -n $output ]]; then
  output_dir=$(dirname -- "$output")
  [[ -d $output_dir ]] || die "output directory does not exist: $output_dir"
  cp -- "$report_file" "$output" || die "could not write report: $output"
  chmod 600 -- "$output" || die "could not secure report permissions: $output"
else
  cat "$report_file"
fi

(( finding_count == 0 ))
