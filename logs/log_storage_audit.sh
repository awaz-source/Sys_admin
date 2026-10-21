#!/usr/bin/env bash
# Read-only audit of log storage usage and growth-risk indicators.
#
# Examples:
#   sudo ./log_storage_audit.sh
#   ./log_storage_audit.sh -d /srv/app/logs -m 250 -n 15 -a 3
#   sudo ./log_storage_audit.sh -o log-storage-report.txt

set -uo pipefail
umask 077

log_root="/var/log"
large_mb=100
top_count=20
recent_days=7
output_file=""

usage() {
  cat <<'EOF'
Usage: log_storage_audit.sh [OPTIONS]

Create a read-only report of log-directory disk usage, largest files, files
over a size threshold, recently modified large files, and rotation artifacts.

Options:
  -d DIR     Log directory to inspect (default: /var/log).
  -m MB      Large-file threshold in MiB (default: 100).
  -n COUNT   Maximum rows per file listing (default: 20).
  -a DAYS    Recent modification window in days (default: 7).
  -o FILE    Save the report with mode 600 instead of printing it.
  -h         Show this help.

Run with sudo when protected log files must be included. The script never
deletes, compresses, truncates, or modifies logs.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':d:m:n:a:o:h' option; do
  case "$option" in
    d) log_root=$OPTARG ;;
    m) large_mb=$OPTARG ;;
    n) top_count=$OPTARG ;;
    a) recent_days=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ -d $log_root ]] || die "Log directory does not exist: $log_root"
[[ -r $log_root ]] || die "Log directory is not readable: $log_root"
[[ $large_mb =~ ^[1-9][0-9]*$ ]] || die "MB must be a positive integer."
[[ $top_count =~ ^[1-9][0-9]*$ ]] || die "COUNT must be a positive integer."
[[ $recent_days =~ ^[0-9]+$ ]] || die "DAYS must be a non-negative integer."

for command_name in find sort stat numfmt df; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/log-storage-audit.XXXXXX") || die "Could not create temporary directory."
inventory_file="$work_dir/inventory.tsv"
errors_file="$work_dir/find-errors.txt"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

: >"$inventory_file"
while IFS= read -r -d '' path; do
  size=$(stat -c '%s' -- "$path" 2>>"$errors_file") || continue
  modified=$(stat -c '%Y' -- "$path" 2>>"$errors_file") || continue
  printf '%s\t%s\t%q\n' "$size" "$modified" "$path" >>"$inventory_file"
done < <(find "$log_root" -xdev -type f -print0 2>"$errors_file")

file_count=$(wc -l <"$inventory_file")
total_bytes=$(awk -F '\t' '{sum += $1} END {printf "%.0f", sum + 0}' "$inventory_file")
threshold_bytes=$((large_mb * 1024 * 1024))
recent_cutoff=$(( $(date +%s) - recent_days * 86400 ))
permission_errors=$(wc -l <"$errors_file")

print_rows() {
  local mode=$1
  local rows
  case "$mode" in
    top)
      rows=$(sort -t $'\t' -k1,1nr "$inventory_file" | head -n "$top_count")
      ;;
    large)
      rows=$(awk -F '\t' -v limit="$threshold_bytes" '$1 >= limit' "$inventory_file" |
        sort -t $'\t' -k1,1nr | head -n "$top_count")
      ;;
    recent)
      rows=$(awk -F '\t' -v limit="$threshold_bytes" -v cutoff="$recent_cutoff" \
        '$1 >= limit && $2 >= cutoff' "$inventory_file" |
        sort -t $'\t' -k2,2nr | head -n "$top_count")
      ;;
  esac

  if [[ -z $rows ]]; then
    printf 'None found.\n'
    return
  fi
  while IFS=$'\t' read -r size modified path; do
    printf '%-10s %s  %s\n' "$(numfmt --to=iec-i --suffix=B "$size")" \
      "$(date -d "@$modified" '+%Y-%m-%d %H:%M:%S')" "$path"
  done <<< "$rows"
}

compressed_count=$(find "$log_root" -xdev -type f \
  \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.zst' \) \
  -print 2>/dev/null | wc -l)
numbered_rotation_count=$(find "$log_root" -xdev -type f \
  \( -name '*.[0-9]' -o -name '*.[0-9][0-9]' \) -print 2>/dev/null | wc -l)

{
  printf 'Log Storage Audit\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Root: %s\n\n' "$(realpath -- "$log_root" 2>/dev/null || printf '%s' "$log_root")"

  printf 'Summary\n'
  printf 'Files inventoried: %s\n' "$file_count"
  printf 'Combined file size: %s\n' "$(numfmt --to=iec-i --suffix=B "$total_bytes")"
  printf 'Large-file threshold: %s MiB\n' "$large_mb"
  printf 'Compressed rotation files: %s\n' "$compressed_count"
  printf 'Numbered rotation files: %s\n' "$numbered_rotation_count"
  printf 'Unreadable/stat errors: %s\n\n' "$permission_errors"

  printf 'Filesystem capacity\n'
  df -hP -- "$log_root" | head -n 2
  printf '\nLargest files (size, modified, escaped path)\n'
  print_rows top
  printf '\nFiles at or above %s MiB\n' "$large_mb"
  print_rows large
  printf '\nLarge files modified within %s day(s)\n' "$recent_days"
  print_rows recent

  printf '\nReview guidance\n'
  printf '%s\n' '- Investigate unexpected growth before disk pressure becomes critical.'
  printf '%s\n' '- Confirm logrotate or application-native retention covers large files.'
  printf '%s\n' '- Preserve required audit and incident-response retention before cleanup.'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
