#!/usr/bin/env bash
# Audit SUID/SGID executables against an optional known-good allowlist.
# Use only on systems you own or are authorized to assess.
#
# Usage:
#   suid_sgid_security_audit.sh [-r ROOT] [-a ALLOWLIST] [-o REPORT]
#
# Options:
#   -r ROOT       Filesystem tree to inspect (default: /). The scan stays on one filesystem.
#   -a ALLOWLIST  File containing one expected absolute path per line.
#                 Blank lines and lines beginning with # are ignored.
#   -o REPORT     Save the report with mode 600 instead of printing it.
#   -h            Show this help.
#
# Results are HIGH for world-writable privileged executables, REVIEW for entries
# absent from the allowlist, and OK for allowlisted entries. Exit codes are
# 0 for no findings, 1 for findings, and 2 for invalid input or scan failure.

set -uo pipefail
umask 077

usage() {
  sed -n '2,17s/^# \{0,1\}//p' "$0"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

scan_root='/'
allowlist=''
output=''
while getopts ':r:a:o:h' option; do
  case "$option" in
    r) scan_root=$OPTARG ;;
    a) allowlist=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "-$OPTARG requires an argument" ;;
    \?) die "unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))
(( $# == 0 )) || die 'unexpected positional arguments'
[[ -d $scan_root ]] || die "scan root is not a directory: $scan_root"
if [[ -n $allowlist ]]; then
  [[ -r $allowlist ]] || die "cannot read allowlist: $allowlist"
fi

for command in cat chmod cp date dirname find mktemp rm sort stat; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

declare -A expected=()
if [[ -n $allowlist ]]; then
  while IFS= read -r entry || [[ -n $entry ]]; do
    [[ $entry =~ ^[[:space:]]*$ || $entry =~ ^[[:space:]]*# ]] && continue
    [[ $entry == /* ]] || die "allowlist path must be absolute: $entry"
    expected["$entry"]=1
  done <"$allowlist"
fi

work_dir=$(mktemp -d) || die 'could not create temporary directory'
trap 'rm -rf -- "$work_dir"' EXIT
found_file=$work_dir/found
rows_file=$work_dir/rows
report_file=$work_dir/report

if ! find "$scan_root" -xdev -type f -perm /6000 -print0 >"$found_file"; then
  die "could not complete scan of: $scan_root"
fi

findings=0
total=0
: >"$rows_file"
while IFS= read -r -d '' path; do
  ((total += 1))
  mode=$(stat -c '%a' -- "$path") || die "could not read mode: $path"
  owner=$(stat -c '%U' -- "$path") || die "could not read owner: $path"
  group=$(stat -c '%G' -- "$path") || die "could not read group: $path"
  symbolic=$(stat -c '%A' -- "$path") || die "could not read permissions: $path"

  if [[ $scan_root == '/' ]]; then
    display_path=$path
  else
    display_path=/${path#"${scan_root%/}"/}
  fi

  status='OK'
  reason='allowlisted'
  # The final character triplet contains the permissions for other users.
  if [[ ${symbolic:8:1} == w ]]; then
    status='HIGH'
    reason='world-writable privileged executable'
    ((findings += 1))
  elif [[ -z ${expected["$display_path"]+present} ]]; then
    status='REVIEW'
    reason='not present in allowlist'
    ((findings += 1))
  fi

  clean_path=${display_path//$'\t'/ }
  clean_path=${clean_path//$'\n'/ }
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$status" "$mode" "$owner" "$group" "$clean_path" "$reason" >>"$rows_file"
done <"$found_file"

sort -t $'\t' -k1,1 -k5,5 "$rows_file" -o "$rows_file" || die 'could not sort results'

{
  printf 'SUID/SGID security audit\n'
  printf 'Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Scan root: %s\n' "$scan_root"
  printf 'Allowlist: %s\n\n' "${allowlist:-none}"
  printf '%-8s %-6s %-12s %-12s %-45s %s\n' 'STATUS' 'MODE' 'OWNER' 'GROUP' 'PATH' 'REASON'
  printf '%-8s %-6s %-12s %-12s %-45s %s\n' '--------' '------' '------------' '------------' '---------------------------------------------' '------'
  while IFS=$'\t' read -r status mode owner group path reason; do
    printf '%-8s %-6s %-12s %-12s %-45s %s\n' "$status" "$mode" "$owner" "$group" "$path" "$reason"
  done <"$rows_file"
  printf '\nSummary: %d privileged executables; %d findings\n' "$total" "$findings"
} >"$report_file"

if [[ -n $output ]]; then
  output_dir=$(dirname -- "$output")
  [[ -d $output_dir ]] || die "output directory does not exist: $output_dir"
  cp -- "$report_file" "$output" || die "could not write report: $output"
  chmod 600 -- "$output" || die "could not secure report permissions: $output"
else
  cat "$report_file"
fi

(( findings == 0 ))
