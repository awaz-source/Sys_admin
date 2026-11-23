#!/usr/bin/env bash
# Summarize systemd unit failures and restart churn from journal text.
# Read-only: this script does not start, stop, reset, or restart any unit.
#
# Examples:
#   sudo ./systemd_unit_churn_report.sh
#   ./systemd_unit_churn_report.sh -s "24 hours ago" -r 5
#   ./systemd_unit_churn_report.sh -f exported-journal.txt -o unit-churn.txt
#
# Exit codes: 0 thresholds not met, 1 units require review, 2 input/collection error.

set -uo pipefail
umask 077

input_file=""
since="24 hours ago"
line_limit=20000
failure_threshold=1
restart_threshold=3
output=""

usage() {
  cat <<'USAGE'
Usage: systemd_unit_churn_report.sh [options]

Options:
  -f FILE    Parse exported journal text instead of the live journal
  -s TIME    journalctl --since value (default: 24 hours ago)
  -n LINES   Maximum trailing input lines to parse (default: 20000)
  -F COUNT   Failure-event threshold per unit (default: 1)
  -r COUNT   Scheduled-restart threshold per unit (default: 3)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

Recognized units include services, sockets, timers, mounts, targets, paths,
automounts, and slices. The report detects common systemd start, stop, failure,
and scheduled-restart messages. Correlate flagged units with application logs,
configuration changes, package activity, and approved maintenance.
USAGE
}

while getopts ":f:s:n:F:r:o:h" option; do
  case "$option" in
    f) input_file=$OPTARG ;;
    s) since=$OPTARG ;;
    n) line_limit=$OPTARG ;;
    F) failure_threshold=$OPTARG ;;
    r) restart_threshold=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

for numeric_value in "$line_limit" "$failure_threshold" "$restart_threshold"; do
  if [[ ! $numeric_value =~ ^[1-9][0-9]*$ ]]; then
    printf 'LINES and threshold values must be positive integers: %s\n' "$numeric_value" >&2
    exit 2
  fi
done

tmp_input=$(mktemp)
tmp_events=$(mktemp)
tmp_summary=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_input" "$tmp_events" "$tmp_summary" "$tmp_findings" "$tmp_report"' EXIT

if [[ -n $input_file ]]; then
  if [[ ! -f $input_file || ! -r $input_file ]]; then
    printf 'Input is not a readable regular file: %s\n' "$input_file" >&2
    exit 2
  fi
  tail -n "$line_limit" -- "$input_file" >"$tmp_input" || exit 2
  source_label=$input_file
else
  command -v journalctl >/dev/null 2>&1 || {
    printf 'journalctl was not found; use -f with exported journal text.\n' >&2
    exit 2
  }
  if ! journalctl --since "$since" --no-pager -o short-iso 2>/dev/null \
    | tail -n "$line_limit" >"$tmp_input"; then
    printf 'Unable to read the system journal.\n' >&2
    exit 2
  fi
  source_label="journalctl since $since"
fi

parsed_line_count=0
while IFS= read -r line || [[ -n $line ]]; do
  parsed_line_count=$((parsed_line_count + 1))
  if [[ ! $line =~ ([A-Za-z0-9_.@:-]+\.(service|socket|timer|mount|target|path|automount|slice)) ]]; then
    continue
  fi
  unit=${BASH_REMATCH[1]}
  event=""
  lower_line=${line,,}

  if [[ $lower_line == *"failed to start"* \
    || $lower_line == *"failed to stop"* \
    || $lower_line == *"failed with result"* \
    || $lower_line == *"entered failed state"* \
    || $lower_line == *"start request repeated too quickly"* ]]; then
    event=FAILURE
  elif [[ $lower_line == *"scheduled restart job"* \
    || $lower_line == *"restart counter is at"* ]]; then
    event=RESTART
  elif [[ $lower_line == *"started "* ]]; then
    event=START
  elif [[ $lower_line == *"stopped "* ]]; then
    event=STOP
  fi

  [[ -n $event ]] || continue
  safe_line=${line//$'\t'/ }
  safe_line=${safe_line//$'\n'/ }
  printf '%s\t%s\t%s\n' "$unit" "$event" "$safe_line" >>"$tmp_events"
done <"$tmp_input"

awk -F'\t' '
  {
    unit=$1
    total[unit]++
    if ($2 == "START") starts[unit]++
    else if ($2 == "STOP") stops[unit]++
    else if ($2 == "FAILURE") failures[unit]++
    else if ($2 == "RESTART") restarts[unit]++
  }
  END {
    for (unit in total)
      printf "%s\t%d\t%d\t%d\t%d\t%d\n", unit, total[unit], starts[unit]+0,
        stops[unit]+0, failures[unit]+0, restarts[unit]+0
  }
' "$tmp_events" | sort -t $'\t' -k1,1 >"$tmp_summary"

event_count=$(wc -l <"$tmp_events")
unit_count=$(wc -l <"$tmp_summary")
finding_count=0
high_count=0
medium_count=0

while IFS=$'\t' read -r unit total starts stops failures restarts; do
  [[ -n $unit ]] || continue
  if (( failures >= failure_threshold )); then
    printf 'HIGH\t%s\t%d failure event(s); %d scheduled restart event(s)\n' \
      "$unit" "$failures" "$restarts" >>"$tmp_findings"
    finding_count=$((finding_count + 1))
    high_count=$((high_count + 1))
  elif (( restarts >= restart_threshold )); then
    printf 'MEDIUM\t%s\t%d scheduled restart events indicate possible churn\n' \
      "$unit" "$restarts" >>"$tmp_findings"
    finding_count=$((finding_count + 1))
    medium_count=$((medium_count + 1))
  fi
done <"$tmp_summary"

{
  printf 'systemd Unit Failure and Churn Report\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Input source: %s\n' "$source_label"
  printf 'Input lines parsed: %d\n' "$parsed_line_count"
  printf 'Recognized unit events: %d across %d unit(s)\n' "$event_count" "$unit_count"
  printf 'Review findings: %d (high: %d, medium: %d)\n' \
    "$finding_count" "$high_count" "$medium_count"

  printf '\n== Unit activity summary ==\n'
  if (( unit_count == 0 )); then
    printf 'No recognized systemd unit lifecycle events were found.\n'
  else
    printf 'UNIT | TOTAL | STARTS | STOPS | FAILURES | SCHEDULED RESTARTS\n'
    tr '\t' '|' <"$tmp_summary"
  fi

  printf '\n== Units requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No unit met the configured failure or restart-churn thresholds.\n'
  else
    printf 'SEVERITY | UNIT | REASON\n'
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" | tr '\t' '|'
  fi

  printf '\n== Matching event timeline ==\n'
  if (( event_count == 0 )); then
    printf 'No matching events.\n'
  else
    printf 'UNIT | EVENT | ORIGINAL LOG LINE\n'
    tr '\t' '|' <"$tmp_events"
  fi

  printf '\n== Investigation guidance ==\n'
  printf 'Review systemctl status, journalctl -u UNIT, recent configuration, and package changes.\n'
  printf 'Confirm resource limits, dependencies, credentials, and restart policy before remediation.\n'
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
