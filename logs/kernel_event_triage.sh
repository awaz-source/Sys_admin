#!/usr/bin/env bash
# Group high-signal Linux kernel events for operational and incident triage.
#
# Examples:
#   sudo ./kernel_event_triage.sh
#   sudo ./kernel_event_triage.sh -s "7 days ago" -n 20
#   ./kernel_event_triage.sh -f kernel.log -o kernel-triage.txt
#
# Exit codes: 0 no categorized events, 1 review events present, 2 input error.

set -uo pipefail
umask 077

since="24 hours ago"
input_file=""
sample_limit=10
output=""

usage() {
  cat <<'USAGE'
Usage: kernel_event_triage.sh [-s SINCE] [-f LOG_FILE] [-n COUNT] [-o REPORT]

Options:
  -s SINCE     journalctl time expression (default: 24 hours ago)
  -f LOG_FILE  Analyze an exported kernel log instead of journalctl
  -n COUNT     Maximum sample events per category (default: 10)
  -o REPORT    Save the report with permissions set to 600
  -h           Show this help

The script is read-only. It groups indicators for review; it does not establish
root cause. Correlate results with hardware telemetry, service logs, monitoring,
and recent maintenance activity.
USAGE
}

while getopts ":s:f:n:o:h" option; do
  case "$option" in
    s) since=$OPTARG ;;
    f) input_file=$OPTARG ;;
    n) sample_limit=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $sample_limit =~ ^[1-9][0-9]*$ ]]; then
  printf 'COUNT must be a positive integer.\n' >&2
  exit 2
fi
if [[ -z $since ]]; then
  printf 'SINCE cannot be empty.\n' >&2
  exit 2
fi

tmp_input=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_input" "$tmp_report"' EXIT

if [[ -n $input_file ]]; then
  if [[ ! -r $input_file ]]; then
    printf 'Kernel log is not readable: %s\n' "$input_file" >&2
    exit 2
  fi
  cp -- "$input_file" "$tmp_input"
  source_description=$input_file
else
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl is required when -f is not supplied.\n' >&2
    exit 2
  fi
  if ! journalctl -k --since "$since" --no-pager -o short-iso >"$tmp_input" 2>/dev/null; then
    printf 'Unable to read kernel journal. Try running with sudo.\n' >&2
    exit 2
  fi
  source_description="kernel journal since: $since"
fi

awk -v limit="$sample_limit" -v source="$source_description" '
  function capture(category, event) {
    counts[category]++
    matched++
    if (sample_counts[category] < limit) {
      sample_counts[category]++
      samples[category SUBSEP sample_counts[category]] = event
    }
  }
  BEGIN {
    categories[1] = "Memory pressure and OOM"
    categories[2] = "Storage and filesystem"
    categories[3] = "Hardware and thermal"
    categories[4] = "Network device"
    categories[5] = "Kernel security denial"
    categories[6] = "Crash, lockup, and panic"

    print "Kernel Event Triage Report"
    print "Source: " source
  }
  {
    total++
    lower = tolower($0)

    if (lower ~ /out of memory|oom-killer|killed process [0-9]+/) {
      capture(categories[1], $0)
    } else if (lower ~ /i\/o error|buffer i\/o|blk_update_request|filesystem error|ext[234]-fs error|xfs.*(corrupt|error)|btrfs.*(corrupt|error)|nvme.*(error|timeout)|ata[0-9].*(error|failed)/) {
      capture(categories[2], $0)
    } else if (lower ~ /machine check|hardware error|mce:|edac.*error|thermal.*critical|overheat/) {
      capture(categories[3], $0)
    } else if (lower ~ /link is down|nic link is down|netdev watchdog|transmit queue.*timed out|tx timeout/) {
      capture(categories[4], $0)
    } else if (lower ~ /avc:.*denied|apparmor=.*denied|audit.*denied/) {
      capture(categories[5], $0)
    } else if (lower ~ /kernel panic|general protection fault|segfault|soft lockup|hard lockup|hung task|call trace:|kernel bug/) {
      capture(categories[6], $0)
    }
  }
  END {
    print "Total lines inspected: " total + 0
    print "Matched critical events: " matched + 0

    print ""
    print "== Category counts =="
    for (i = 1; i <= 6; i++) {
      category = categories[i]
      printf "%4d  %s\n", counts[category] + 0, category
    }

    for (i = 1; i <= 6; i++) {
      category = categories[i]
      print ""
      print "== " category " samples =="
      if (sample_counts[category] == 0) {
        print "None found."
      } else {
        for (j = 1; j <= sample_counts[category]; j++) {
          print samples[category SUBSEP j]
        }
        if (counts[category] > sample_counts[category]) {
          print "[Additional events omitted: " counts[category] - sample_counts[category] "]"
        }
      }
    }

    print ""
    print "== Review guidance =="
    if (matched == 0) {
      print "No events matched the configured high-signal patterns."
    } else {
      print "Review timestamps and recurrence; correlate with workload, hardware, security, and maintenance telemetry."
    }
  }
' "$tmp_input" >"$tmp_report"

finding_count=$(awk -F': ' '/^Matched critical events:/ {print $2 + 0}' "$tmp_report")

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( finding_count == 0 )) && exit 0
exit 1
