#!/usr/bin/env bash
# Verify that expected backup artifacts exist, are recent, and meet a minimum size.
#
# Usage:
#   backup_verification_report.sh -c CHECKLIST [-o REPORT]
#
# CHECKLIST is tab-delimited, with one backup per line:
#   LABEL<TAB>PATH<TAB>MAX_AGE_HOURS<TAB>MIN_BYTES
# PATH may be a file or directory. For a directory, the newest regular file
# below it is checked. Blank lines and lines beginning with # are ignored.
#
# Exit codes: 0 all checks pass; 1 one or more backup checks fail;
#             2 invalid input or an inspection error.

set -uo pipefail
umask 077

usage() {
  sed -n '2,13s/^# \{0,1\}//p' "$0"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

checklist=''
output=''
while getopts ':c:o:h' option; do
  case "$option" in
    c) checklist=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "-$OPTARG requires an argument" ;;
    \?) die "unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die 'unexpected positional arguments'
[[ -n $checklist ]] || die 'a checklist is required (-c CHECKLIST)'
[[ -r $checklist ]] || die "cannot read checklist: $checklist"

for command in date find stat mktemp; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

work_dir=$(mktemp -d) || die 'could not create temporary directory'
trap 'rm -rf -- "$work_dir"' EXIT
report_file=$work_dir/report
candidate_file=$work_dir/candidates
now=$(date +%s) || die 'could not read the current time'
failures=0
rows=0

sanitize() {
  local value=$1
  value=${value//$'\t'/ }
  value=${value//$'\n'/ }
  printf '%s' "$value"
}

printf 'Backup verification report\nGenerated: %s\nChecklist: %s\n\n' \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$checklist" >"$report_file"
printf '%-20s %-8s %-10s %-12s %s\n' 'LABEL' 'STATUS' 'AGE_HOURS' 'BYTES' 'ARTIFACT' >>"$report_file"
printf '%-20s %-8s %-10s %-12s %s\n' '--------------------' '--------' '----------' '------------' '--------' >>"$report_file"

line_number=0
while IFS= read -r line || [[ -n $line ]]; do
  ((line_number += 1))
  [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue

  IFS=$'\t' read -r label path max_age min_bytes extra <<<"$line"
  [[ -n ${label:-} && -n ${path:-} && -n ${max_age:-} && -n ${min_bytes:-} && -z ${extra:-} ]] || \
    die "invalid checklist row $line_number: expected exactly four tab-delimited fields"
  [[ $max_age =~ ^[0-9]+$ ]] || die "invalid maximum age on row $line_number"
  [[ $min_bytes =~ ^[0-9]+$ ]] || die "invalid minimum size on row $line_number"

  ((rows += 1))
  artifact=''
  status='OK'
  reason=''

  if [[ -f $path ]]; then
    artifact=$path
  elif [[ -d $path ]]; then
    : >"$candidate_file"
    find "$path" -type f -print0 >"$candidate_file" || die "could not inspect directory on row $line_number: $path"
    newest=-1
    while IFS= read -r -d '' candidate; do
      candidate_mtime=$(stat -c %Y -- "$candidate") || die "could not stat: $candidate"
      if (( candidate_mtime > newest )); then
        newest=$candidate_mtime
        artifact=$candidate
      fi
    done <"$candidate_file"
  fi

  if [[ -z $artifact ]]; then
    status='FAIL'
    reason='missing path or directory contains no files'
    age='-'
    bytes='-'
    ((failures += 1))
  else
    mtime=$(stat -c %Y -- "$artifact") || die "could not read modification time: $artifact"
    bytes=$(stat -c %s -- "$artifact") || die "could not read size: $artifact"
    (( mtime > now )) && age=0 || age=$(( (now - mtime) / 3600 ))
    if (( age > max_age )); then
      status='FAIL'
      reason="older than ${max_age}h"
    fi
    if (( bytes < min_bytes )); then
      status='FAIL'
      [[ -n $reason ]] && reason+=', '
      reason+="smaller than ${min_bytes} bytes"
    fi
    [[ $status == OK ]] || ((failures += 1))
  fi

  safe_label=$(sanitize "$label")
  safe_artifact=$(sanitize "${artifact:-$path}")
  printf '%-20.20s %-8s %-10s %-12s %s\n' "$safe_label" "$status" "$age" "$bytes" "$safe_artifact" >>"$report_file"
  [[ -z $reason ]] || printf '  Reason: %s\n' "$reason" >>"$report_file"
  if [[ -n $artifact ]] && command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum -- "$artifact") || die "could not checksum: $artifact"
    printf '  SHA256: %s\n' "${digest%% *}" >>"$report_file"
  fi
done <"$checklist"

(( rows > 0 )) || die 'checklist contains no backup entries'
printf '\nSummary: %d checked, %d failed\n' "$rows" "$failures" >>"$report_file"

if [[ -n $output ]]; then
  output_dir=$(dirname -- "$output")
  [[ -d $output_dir ]] || die "output directory does not exist: $output_dir"
  cp -- "$report_file" "$output" || die "could not write report: $output"
  chmod 600 -- "$output" || die "could not secure report permissions: $output"
else
  cat "$report_file"
fi

(( failures == 0 ))
