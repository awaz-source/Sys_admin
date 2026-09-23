#!/usr/bin/env bash
# Build a compact report from high-priority systemd journal entries.
#
# Usage:
#   ./journal_error_report.sh
#   ./journal_error_report.sh -s "2 hours ago" -u sshd -n 100
#   sudo ./journal_error_report.sh -s "yesterday" -o /tmp/journal-report.txt
#
# Options:
#   -s TIME    journalctl --since value (default: 24 hours ago)
#   -u UNIT    restrict the report to one systemd unit
#   -n COUNT   maximum recent entries to include (default: 50)
#   -o FILE    write the report to FILE instead of standard output
#   -h         show help

set -uo pipefail

since="24 hours ago"
unit=""
max_entries=50
output_file=""

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":s:u:n:o:h" option; do
  case "$option" in
    s) since=$OPTARG ;;
    u) unit=$OPTARG ;;
    n) max_entries=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h)
      usage
      exit 0
      ;;
    :)
      printf 'Error: -%s requires a value.\n' "$OPTARG" >&2
      usage >&2
      exit 2
      ;;
    \?)
      printf 'Error: unknown option -%s.\n' "$OPTARG" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ $max_entries =~ ^[1-9][0-9]*$ ]]; then
  printf 'Error: -n must be a positive integer.\n' >&2
  exit 2
fi

if ! command -v journalctl >/dev/null 2>&1; then
  printf 'Error: journalctl is required.\n' >&2
  exit 2
fi

journal_args=(
  --since "$since"
  --priority err..alert
  --no-pager
  --output short-iso
  --lines "$max_entries"
)

if [[ -n $unit ]]; then
  journal_args+=(--unit "$unit")
fi

entries_file=$(mktemp)
report_file=$(mktemp)
trap 'rm -f "$entries_file" "$report_file"' EXIT

if ! journalctl "${journal_args[@]}" >"$entries_file"; then
  printf 'Error: journalctl could not read the requested entries.\n' >&2
  printf 'Try running the script with sudo or adding the user to systemd-journal.\n' >&2
  exit 1
fi

# Some journalctl versions print this marker to standard output when the
# journal is empty. Remove it so the report correctly records zero entries.
sed -i '/^-- No entries --$/d' "$entries_file"

entry_count=$(awk 'NF { count++ } END { print count + 0 }' "$entries_file")

{
  printf 'SYSTEMD JOURNAL ERROR REPORT\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname)"
  printf 'Since: %s\n' "$since"
  printf 'Unit: %s\n' "${unit:-all units}"
  printf 'Entries included: %s\n\n' "$entry_count"

  printf 'TOP LOG SOURCES\n'
  if (( entry_count == 0 )); then
    printf 'No error-priority journal entries matched.\n'
  else
    awk '
      NF >= 3 {
        source=$3
        sub(/\[[0-9]+\]:?$/, "", source)
        sub(/:$/, "", source)
        counts[source]++
      }
      END {
        for (source in counts) {
          printf "%7d  %s\n", counts[source], source
        }
      }
    ' "$entries_file" | sort -nr | head -10
  fi

  printf '\nRECENT ERROR-PRIORITY ENTRIES\n'
  if (( entry_count == 0 )); then
    printf 'None.\n'
  else
    cat "$entries_file"
  fi
} >"$report_file"

if [[ -n $output_file ]]; then
  if ! install -m 600 "$report_file" "$output_file"; then
    printf 'Error: could not write report to %s.\n' "$output_file" >&2
    exit 1
  fi
  printf 'Report written to %s\n' "$output_file"
else
  cat "$report_file"
fi
