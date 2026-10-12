#!/usr/bin/env bash
# Create a read-only first-response report for a suspicious file.
# The script never executes or uploads the sample.
#
# Examples:
#   ./file_triage_report.sh /tmp/suspicious.bin
#   ./file_triage_report.sh -n 100 -o sample-report.txt ./unknown.sh

set -uo pipefail
umask 077

output_file=""
max_strings=50

usage() {
  cat <<'EOF'
Usage: file_triage_report.sh [-n COUNT] [-o REPORT] FILE

Collect metadata, cryptographic hashes, detected type, printable strings, and
basic indicators from FILE without executing or uploading it.

Options:
  -n COUNT   Maximum printable strings and indicators per section (default: 50).
  -o FILE    Save the report with mode 600 instead of printing to stdout.
  -h         Show this help.

Required commands: stat, file, sha256sum, sha1sum, md5sum, strings.
For incident-response integrity, analyze a copy and record the original source.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':n:o:h' option; do
  case "$option" in
    n) max_strings=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 1 )) || die "Specify exactly one file to analyze."
sample=$1
[[ -f $sample ]] || die "Not a regular file: $sample"
[[ -r $sample ]] || die "File is not readable: $sample"
[[ $max_strings =~ ^[1-9][0-9]*$ ]] || die "COUNT must be a positive integer."

for command_name in stat file sha256sum sha1sum md5sum strings; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/file-triage.XXXXXX") || die "Could not create temporary directory."
strings_file="$work_dir/strings.txt"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

# Extract once so every section examines the same bytes.
strings -a -n 6 -- "$sample" >"$strings_file" || die "Could not extract strings from the file."

print_matches() {
  local expression=$1
  local matches
  matches=$(grep -Eio -- "$expression" "$strings_file" | sort -u | head -n "$max_strings" || true)
  [[ -n $matches ]] && printf '%s\n' "$matches" || printf 'None found.\n'
}

{
  printf 'Suspicious File Triage Report\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Analyst host: %s\n\n' "$(hostname 2>/dev/null || printf unknown)"

  printf 'File metadata\n'
  printf 'Path: %s\n' "$(realpath -- "$sample" 2>/dev/null || printf '%s' "$sample")"
  stat --printf='Size: %s bytes\nOwner: %U (%u)\nGroup: %G (%g)\nMode: %A (%a)\nModified: %y\nChanged: %z\n' -- "$sample"
  printf 'Detected type: %s\n\n' "$(file -b -- "$sample")"

  printf 'Cryptographic hashes\n'
  printf 'MD5: %s\n' "$(md5sum -- "$sample" | awk '{print $1}')"
  printf 'SHA1: %s\n' "$(sha1sum -- "$sample" | awk '{print $1}')"
  printf 'SHA256: %s\n\n' "$(sha256sum -- "$sample" | awk '{print $1}')"

  printf 'Embedded URLs (unique, first %s)\n' "$max_strings"
  print_matches 'https?://[^[:space:]"<>]+'
  printf '\nIPv4-like addresses (unique, first %s)\n' "$max_strings"
  print_matches '([0-9]{1,3}\.){3}[0-9]{1,3}'
  printf '\nEmail-like addresses (unique, first %s)\n' "$max_strings"
  print_matches '[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'

  printf '\nPrintable strings (minimum length 6, first %s)\n' "$max_strings"
  if [[ -s $strings_file ]]; then
    head -n "$max_strings" "$strings_file"
  else
    printf 'None found.\n'
  fi

  printf '\nAnalyst notes\n'
  printf 'Verdict: _Pending_\n'
  printf 'Source/context: _Not recorded_\n'
  printf 'Recommended next step: Validate hashes in approved threat-intelligence sources.\n'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
